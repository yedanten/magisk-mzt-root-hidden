// 闽政通 root 检测"反应层"屏蔽 —— Zygisk 原生模块 v7
//
// v7 修复（重要）：
//   v6 用 ArtMethod 改写把 android.app.Dialog.show() 换成了 native 桩，再想通过
//   CallNonvirtualVoidMethod(备份的 ArtMethod 副本) 回调原实现 —— 实测**回调不生效**：
//   原 show() 里的 dispatchOnCreate()/addView() 都没执行，于是任何自定义 Dialog 的
//   onCreate 不跑、布局不加载、窗口不添加。表现为：
//     点"获取验证码" → 服务端返回成功 → 应用要弹滑块验证码 BlockPuzzleDialog →
//     BlockPuzzleDialog.d() 里 DragImageView 为 null → NPE →
//     被 com.wanjian.cockroach 防崩溃库吞掉 → 界面毫无反应（点"登录"同理）。
//   结论：**不要再 hook android.app.Dialog.show()**。要压警告弹窗只能从
//   AlertDialog.Builder.show() 这类"调用点"下手（本模块保留该处抑制）。
//
// 已确认的事实（详见分析报告附录 A/B）：
//   1) 该壳识别 LSPosed/Xposed/Frida 注入并主动 SIGSEGV ⇒ 只能用 Zygisk 原生模块；
//   2) 应用主进程走 USAP，Zygisk 的 pre/postAppSpecialize 不触发 ⇒ 钩子必须在 onLoad(zygote) 装好，
//      由 fork 继承；拦截判定放在钩子内部按 /proc/self/cmdline 判断目标包；
//   3) 判到 root 后的反应链（Cockroach 抓到的真实堆栈）：
//        DECBackgroundTask$1$1.run -> DeviceEnvironmentCheck$1.onPostExecute
//        -> DeviceEnvironmentCheck$1$1.run { 关界面 / 退出 / Process.killProcess }
//   4) 反应约在启动后 10.6s 发生；主进程观察到的是"自己 finish 掉 Activity + 进程退出"。
//
// v3 相比 v2：
//   - 修正 ArtMethod 补丁的类加载器错误：必须用应用 ClassLoader.loadClass()，
//     在 native 线程里 FindClass("com/a/b/c/...") 一定失败（那是 boot classloader）；
//   - 增加"主进程必然被调用"的触发点：PLT hook __system_property_get（框架启动就读属性）；
//   - 增加 exit/_exit/exit_group 观测（先只记录，用于确认反应到底走哪条退出路径）；
//   - 每个钩子都写标记文件，便于判断"钩子是否被 USAP 主进程继承/调用"。
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

#include "zygisk.hpp"

#define TAG "MztKill"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ModuleBase;

static const char *kTargetPkg = "net.evecom.android.mztapp";
static const char *kMarkerPath = "/data/data/net.evecom.android.mztapp/cache/mztkill.log";

// ArtMethod 布局（Android 11~14，64 位 + 压缩引用）
static const size_t kOffAccessFlags = 4;
static const size_t kOffData = 16;
static const size_t kOffEntryPoint = 24;
static const uint32_t kAccNative = 0x0100;

static JavaVM *g_vm = nullptr;
static int (*g_orig_kill)(pid_t, int) = nullptr;
static int (*g_orig_tgkill)(pid_t, pid_t, int) = nullptr;
static void (*g_orig_sendSignal)(JNIEnv *, jclass, jint, jint) = nullptr;
static jstring (*g_orig_native_get)(JNIEnv *, jclass, jstring, jstring) = nullptr;
static void (*g_orig_setArgV0)(JNIEnv *, jclass, jstring) = nullptr;
static jint (*g_orig_myPid)() = nullptr;
static void (*g_orig_nativePollOnce)(JNIEnv *, jobject, jlong, jint) = nullptr;
static int (*g_orig_prop_get)(const char *, char *) = nullptr;
static void (*g_orig_exit)(int) = nullptr;
static void (*g_orig__exit)(int) = nullptr;
static void (*g_orig_exit_group)(int) = nullptr;
static int g_hooks_installed = 0;
static volatile int g_patch_started = 0;
static void *g_jni_trampoline = nullptr;

// ---------------------------------------------------------------- utils
static void read_self_cmdline(char *out, size_t n) {
    out[0] = '\0';
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t r = read(fd, out, n - 1);
    close(fd);
    if (r <= 0) { out[0] = '\0'; return; }
    out[r] = '\0';
}

// 目标判断：带缓存，但"尚未 specialize"的进程名（zygote64 / <pre-initialized> / 空）绝不缓存，
// 否则应用进程会在 specialize 期间就把自己判成"非目标"而永久失效（这是真实踩过的坑）。
static void diag(const char *fmt, ...);

static void diag(const char *fmt, ...) {
    int fd = open("/data/local/tmp/mztkill_boot.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    if (fd < 0) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) { ssize_t w = write(fd, buf, (size_t)n); (void)w; }
    close(fd);
}


static volatile int g_target_state = -1;  // -1 未知, 0 否, 1 是

static int is_target_proc(void) {
    int s = __atomic_load_n(&g_target_state, __ATOMIC_RELAXED);
    if (s >= 0) return s;

    char cmd[256];
    read_self_cmdline(cmd, sizeof(cmd));
    if (cmd[0] == '\0' || strstr(cmd, "zygote") != nullptr || strstr(cmd, "pre-initialized") != nullptr) {
        return 0;  // 还没 specialize：不判定、不缓存
    }
    s = (strncmp(cmd, kTargetPkg, strlen(kTargetPkg)) == 0) ? 1 : 0;
    __atomic_store_n(&g_target_state, s, __ATOMIC_RELAXED);
    return s;
}

static void marker(const char *what) {
    int fd = open(kMarkerPath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    char cmd[128];
    read_self_cmdline(cmd, sizeof(cmd));
    char buf[384];
    int n = snprintf(buf, sizeof(buf), "%s pid=%d tid=%d cmd=%s\n", what, (int)getpid(), (int)gettid(), cmd);
    if (n > 0) { ssize_t w = write(fd, buf, (size_t)n); (void)w; }
    close(fd);
}

static void note(const char *what) {
    LOGI("%s", what);
    marker(what);
}

// ---------------------------------------------------------------- ArtMethod 改写
static void noop_void(JNIEnv *, jobject) {}
static jobject noop_obj(JNIEnv *, jobject) { return nullptr; }

// 读 AlertDialog.Builder 的 message，判断是不是"root 风险"警告
static int builder_is_root_warning(JNIEnv *env, jobject builder) {
    if (!builder) return 0;
    jclass bc = env->GetObjectClass(builder);
    // Builder.P : AlertController.AlertParams ; AlertParams.mMessage : CharSequence
    jfieldID fidP = env->GetFieldID(bc, "P", "Landroid/app/AlertController$AlertParams;");
    if (!fidP) { env->ExceptionClear(); return 0; }
    jobject params = env->GetObjectField(builder, fidP);
    if (!params) return 0;
    jclass pc = env->GetObjectClass(params);
    jfieldID fidMsg = env->GetFieldID(pc, "mMessage", "Ljava/lang/CharSequence;");
    if (!fidMsg) { env->ExceptionClear(); return 0; }
    jobject msg = env->GetObjectField(params, fidMsg);
    if (!msg) return 0;
    jclass sc = env->FindClass("java/lang/String");
    jmethodID ts = env->GetMethodID(sc, "toString", "()Ljava/lang/String;");
    jstring js = (jstring) env->CallObjectMethod(msg, ts);
    if (!js) { env->ExceptionClear(); return 0; }
    const char *cs = env->GetStringUTFChars(js, nullptr);
    int hit = 0;
    if (cs) {
        if (strstr(cs, "root") || strstr(cs, "ROOT") || strstr(cs, "运行环境")) hit = 1;
        env->ReleaseStringUTFChars(js, cs);
    }
    return hit;
}

static void dump_stack(const char *tag) {
    JNIEnv *env = nullptr;
    if (!g_vm || g_vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK || !env) return;
    jclass te = env->FindClass("java/lang/Throwable");
    jmethodID ctor = te ? env->GetMethodID(te, "<init>", "()V") : nullptr;
    jmethodID gst = te ? env->GetMethodID(te, "getStackTrace", "()[Ljava/lang/StackTraceElement;") : nullptr;
    if (!ctor || !gst) { env->ExceptionClear(); return; }
    jobject th = env->NewObject(te, ctor);
    jobjectArray arr = th ? (jobjectArray) env->CallObjectMethod(th, gst) : nullptr;
    if (!arr) { env->ExceptionClear(); return; }
    jsize n = env->GetArrayLength(arr);
    for (jsize i = 0; i < n && i < 12; i++) {
        jobject e = env->GetObjectArrayElement(arr, i);
        if (!e) continue;
        jclass ec = env->GetObjectClass(e);
        jmethodID ts = env->GetMethodID(ec, "toString", "()Ljava/lang/String;");
        jstring js = ts ? (jstring) env->CallObjectMethod(e, ts) : nullptr;
        if (js) {
            const char *cs = env->GetStringUTFChars(js, nullptr);
            if (cs) { char line[320]; snprintf(line, sizeof(line), "%s %s", tag, cs); marker(line); env->ReleaseStringUTFChars(js, cs); }
        }
        env->DeleteLocalRef(e);
    }
}

// 注意：**不要**去改写 android.app.Dialog.show() 本身（v6 的教训，见文件头 v7 说明）。
//       要让"root 风险"警告框不弹，只能改写 AlertDialog.Builder.show() 这个调用点。

// 替换 AlertDialog.Builder.show()：root 警告直接不弹（并记录调用栈），其它对话框照常 create().show()
static jobject my_builder_show(JNIEnv *env, jobject thiz) {
    if (builder_is_root_warning(env, thiz)) {
        diag("BLOCKED root-warning dialog\n");
        dump_stack("  at");
        return nullptr;
    }
    jclass bc = env->GetObjectClass(thiz);
    jmethodID create = env->GetMethodID(bc, "create", "()Landroid/app/AlertDialog;");
    if (!create) { env->ExceptionClear(); return nullptr; }
    jobject dlg = env->CallObjectMethod(thiz, create);
    if (dlg) {
        jclass dc = env->GetObjectClass(dlg);
        jmethodID show = env->GetMethodID(dc, "show", "()V");
        if (show) env->CallVoidMethod(dlg, show);
    }
    return dlg;
}

static void patch_one(JNIEnv *env, jclass c, const char *name, const char *sig, void *stub) {
    if (!c) return;
    jmethodID mid = env->GetMethodID(c, name, sig);
    if (!mid || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    uint8_t *am = (uint8_t *)mid;
    uint32_t flags = *(uint32_t *)(am + kOffAccessFlags);
    *(void **)(am + kOffData) = stub;                   // JNI 实现 = 空函数
    *(void **)(am + kOffEntryPoint) = g_jni_trampoline;  // 走通用 JNI trampoline
    *(uint32_t *)(am + kOffAccessFlags) = flags | kAccNative;
    LOGI("PATCHED %s%s (oldflags=0x%x)", name, sig, flags);
}

static void patch_all(JNIEnv *env, jobject loader) {
    // 通用 JNI trampoline：从 native 方法 Process.sendSignal 的 ArtMethod 取
    jclass pc = env->FindClass("android/os/Process");
    jmethodID ss = pc ? env->GetStaticMethodID(pc, "sendSignal", "(II)V") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (ss) g_jni_trampoline = *(void **)((uint8_t *)ss + kOffEntryPoint);
    LOGI("jni trampoline = %p", g_jni_trampoline);
    if (!g_jni_trampoline || !loader) return;

    jclass clc = env->FindClass("java/lang/ClassLoader");
    jmethodID lc = clc ? env->GetMethodID(clc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;
    if (!lc) { env->ExceptionClear(); return; }

    struct { const char *cls; const char *name; const char *sig; int obj; } targets[] = {
        {"com.a.b.c.DeviceEnvironmentCheck$1$1", "run", "()V", 0},
        {"com.a.b.c.DeviceEnvironmentCheck$1", "onPostExecute", "(Ljava/lang/Object;)V", 0},
        {"com.a.b.c.DeviceEnvironmentCheck$1", "doInBackground", "([Ljava/lang/Object;)Ljava/lang/Object;", 1},
        {"com.a.b.c.DECBackgroundTask$1$1", "run", "()V", 0},
        {"com.a.b.c.DECBackgroundTask$1", "onPostExecute", "(Ljava/lang/Object;)V", 0},
        {"com.a.b.c.DECBackgroundTask$1", "doInBackground", "([Ljava/lang/Object;)Ljava/lang/Object;", 1},
        {"com.a.b.c.DECMsgDialog", "onCreate", "(Landroid/os/Bundle;)V", 0},
    };
    // android.app.Dialog.show() **不碰**：v6 在这里把原实现换成 native 桩后回调不生效，
    // 使整个应用的 Dialog.onCreate/布局/窗口全部失效（登录验证码弹窗 NPE 的直接原因）。

    // AlertDialog.Builder.show()：单独处理（要按 message 判定，且需要真实返回值）
    {
        jclass abc = env->FindClass("android/app/AlertDialog$Builder");
        if (abc) {
            jmethodID mid = env->GetMethodID(abc, "show", "()Landroid/app/AlertDialog;");
            if (mid && !env->ExceptionCheck()) {
                uint8_t *am = (uint8_t *)mid;
                uint32_t flags = *(uint32_t *)(am + kOffAccessFlags);
                *(void **)(am + kOffData) = (void *)my_builder_show;
                *(void **)(am + kOffEntryPoint) = g_jni_trampoline;
                *(uint32_t *)(am + kOffAccessFlags) = flags | kAccNative;
                LOGI("PATCHED AlertDialog$Builder.show");
                marker("patched-dialog-show");
            } else env->ExceptionClear();
        }
    }

    int patched = 0;
    for (auto &t : targets) {
        jstring nm = env->NewStringUTF(t.cls);
        jobject c = nm ? env->CallObjectMethod(loader, lc, nm) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!c) continue;
        patch_one(env, (jclass)c, t.name, t.sig, t.obj ? (void *)noop_obj : (void *)noop_void);
        patched++;
    }
    LOGI("patch_all done, patched=%d", patched);
    marker(patched ? "patched-dec-methods" : "patch-found-nothing");
}

static void *patch_thread(void *) {
    JNIEnv *env = nullptr;
    if (!g_vm || g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) return nullptr;
    marker("patch-thread-start");

    for (int i = 0; i < 300; i++) {  // 最多 ~30s
        jclass at = env->FindClass("android/app/ActivityThread");
        jmethodID cur = at ? env->GetStaticMethodID(at, "currentApplication", "()Landroid/app/Application;") : nullptr;
        jobject app = cur ? env->CallStaticObjectMethod(at, cur) : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (app) {
            jclass ctx = env->FindClass("android/content/ContextWrapper");
            jmethodID glc = ctx ? env->GetMethodID(ctx, "getClassLoader", "()Ljava/lang/ClassLoader;") : nullptr;
            jobject loader = glc ? env->CallObjectMethod(app, glc) : nullptr;
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (loader) {
                jclass clc = env->FindClass("java/lang/ClassLoader");
                jmethodID lc = clc ? env->GetMethodID(clc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;
                jstring nm = env->NewStringUTF("com.a.b.c.DeviceEnvironmentCheck$1$1");
                jobject c = (lc && nm) ? env->CallObjectMethod(loader, lc, nm) : nullptr;
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (c) {
                    LOGI("DEC classes loaded (iter=%d), patching", i);
                    patch_all(env, loader);
                    break;
                }
            }
        }
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, nullptr);
    }
    g_vm->DetachCurrentThread();
    return nullptr;
}

static void start_patcher(const char *from) {
    // 已知非目标进程：直接返回，保证 __system_property_get 这类热路径零开销
    if (__atomic_load_n(&g_target_state, __ATOMIC_RELAXED) == 0) return;
    if (__atomic_exchange_n(&g_patch_started, 1, __ATOMIC_SEQ_CST)) return;
    if (!is_target_proc()) {
        char c[256];
        read_self_cmdline(c, sizeof(c));
        diag("start_patcher from=%s pid=%d cmd=%s -> not-target\n", from, (int)getpid(), c);
        __atomic_store_n(&g_patch_started, 0, __ATOMIC_SEQ_CST);
        return;
    }
    LOGI("start DEC patcher (from %s, pid=%d)", from, (int)getpid());
    marker("patcher-start");
    pthread_t th;
    if (pthread_create(&th, nullptr, patch_thread, nullptr) == 0) pthread_detach(th);
}

// ---------------------------------------------------------------- 钩子实现
static int my_kill(pid_t pid, int sig) {
    if (sig == SIGKILL && (pid == getpid() || pid == 0) && is_target_proc()) {
        note("BLOCK kill(self,SIGKILL)");
        return 0;
    }
    if (g_orig_kill) return g_orig_kill(pid, sig);
    return (int)syscall(__NR_kill, pid, sig);
}

static int my_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (sig == SIGKILL && tgid == getpid() && is_target_proc()) {
        note("BLOCK tgkill(self,SIGKILL)");
        return 0;
    }
    if (g_orig_tgkill) return g_orig_tgkill(tgid, tid, sig);
    return (int)syscall(__NR_tgkill, tgid, tid, sig);
}

static void my_sendSignal(JNIEnv *env, jclass clazz, jint pid, jint sig) {
    if (sig == SIGKILL && pid == (jint)getpid() && is_target_proc()) {
        note("BLOCK Process.sendSignal(self,SIGKILL)");
        return;
    }
    if (g_orig_sendSignal) g_orig_sendSignal(env, clazz, pid, sig);
}

static jstring my_native_get(JNIEnv *env, jclass clazz, jstring key, jstring def) {
    start_patcher("native_get");
    if (g_orig_native_get) return g_orig_native_get(env, clazz, key, def);
    return def;
}

static void my_setArgV0(JNIEnv *env, jclass clazz, jstring name) {
    start_patcher("setArgV0");
    if (g_orig_setArgV0) g_orig_setArgV0(env, clazz, name);
}

static jint my_myPid() {
    start_patcher("myPid");
    if (g_orig_myPid) return g_orig_myPid();
    return (jint)getpid();
}

// 主线程消息循环每次都会调它（Looper.loop -> MessageQueue.next -> nativePollOnce），
// 这是"应用进程里必然被调用"的可靠触发点。
static void my_nativePollOnce(JNIEnv *env, jobject thiz, jlong ptr, jint timeoutMillis) {
    start_patcher("nativePollOnce");
    if (g_orig_nativePollOnce) g_orig_nativePollOnce(env, thiz, ptr, timeoutMillis);
}

// 框架/应用启动必读系统属性 —— 作为主进程的早期触发点
static int my_prop_get(const char *name, char *value) {
    start_patcher("__system_property_get");
    if (g_orig_prop_get) return g_orig_prop_get(name, value);
    return 0;
}

// 退出路径只观测（判断反应到底怎么退出），不拦
static void my_exit(int code) {
    if (is_target_proc()) { LOGI("exit(%d)", code); marker("exit-called"); }
    if (g_orig_exit) g_orig_exit(code);
    syscall(__NR_exit, code);
    __builtin_unreachable();
}

static void my__exit(int code) {
    if (is_target_proc()) { LOGI("_exit(%d)", code); marker("_exit-called"); }
    if (g_orig__exit) g_orig__exit(code);
    syscall(__NR_exit, code);
    __builtin_unreachable();
}

static void my_exit_group(int code) {
    if (is_target_proc()) { LOGI("exit_group(%d)", code); marker("exit_group-called"); }
    if (g_orig_exit_group) g_orig_exit_group(code);
    syscall(__NR_exit_group, code);
    __builtin_unreachable();
}

static void hook_lib_symbol(Api *api, const char *libname, const char *symbol,
                            void *newFunc, void **oldFunc) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, libname)) continue;
        unsigned int dev_major = 0, dev_minor = 0;
        unsigned long inode = 0;
        if (sscanf(line, "%*s %*s %*s %x:%x %lu", &dev_major, &dev_minor, &inode) == 3 && inode != 0) {
            api->pltHookRegister(makedev(dev_major, dev_minor), (ino_t)inode, symbol, newFunc, oldFunc);
            break;
        }
    }
    fclose(fp);
}

class MztKillModule : public ModuleBase {
    Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;

public:
    void onLoad(Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        if (env && env->GetJavaVM(&g_vm) != JNI_OK) g_vm = nullptr;
        char c[256]; read_self_cmdline(c, sizeof(c));
        diag("onLoad pid=%d cmd=%s\n", (int)getpid(), c);
        installHooks("onLoad");
    }
    void preAppSpecialize(AppSpecializeArgs *) override { installHooks("preAppSpecialize"); }
    void postAppSpecialize(const AppSpecializeArgs *) override {
        installHooks("postAppSpecialize");
        start_patcher("postAppSpecialize");
    }

private:
    void installHooks(const char *where) {
        char cmd[256];
        read_self_cmdline(cmd, sizeof(cmd));
        if (g_hooks_installed) {
            LOGI("[%s] already installed (pid=%d cmd=%s)", where, (int)getpid(), cmd);
            return;
        }
        LOGI("[%s] installing (pid=%d cmd=%s)", where, (int)getpid(), cmd);

        if (env_) {
            JNINativeMethod m1[1] = {{(char *)"sendSignal", (char *)"(II)V", (void *)my_sendSignal}};
            api_->hookJniNativeMethods(env_, "android/os/Process", m1, 1);
            g_orig_sendSignal = (void (*)(JNIEnv *, jclass, jint, jint))m1[0].fnPtr;

            JNINativeMethod m2[1] = {{(char *)"native_get",
                                      (char *)"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                                      (void *)my_native_get}};
            api_->hookJniNativeMethods(env_, "android/os/SystemProperties", m2, 1);
            g_orig_native_get = (jstring(*)(JNIEnv *, jclass, jstring, jstring))m2[0].fnPtr;

            JNINativeMethod m3[1] = {{(char *)"setArgV0", (char *)"(Ljava/lang/String;)V", (void *)my_setArgV0}};
            api_->hookJniNativeMethods(env_, "android/os/Process", m3, 1);
            g_orig_setArgV0 = (void (*)(JNIEnv *, jclass, jstring))m3[0].fnPtr;

            JNINativeMethod m4[1] = {{(char *)"myPid", (char *)"()I", (void *)my_myPid}};
            api_->hookJniNativeMethods(env_, "android/os/Process", m4, 1);
            g_orig_myPid = (jint(*)())m4[0].fnPtr;

            JNINativeMethod m5[1] = {{(char *)"nativePollOnce", (char *)"(JI)V", (void *)my_nativePollOnce}};
            api_->hookJniNativeMethods(env_, "android/os/MessageQueue", m5, 1);
            g_orig_nativePollOnce = (void (*)(JNIEnv *, jobject, jlong, jint))m5[0].fnPtr;
            LOGI("jnihooks sendSignal=%p native_get=%p setArgV0=%p myPid=%p nativePollOnce=%p",
                 (void *)g_orig_sendSignal, (void *)g_orig_native_get, (void *)g_orig_setArgV0, (void *)g_orig_myPid,
                 (void *)g_orig_nativePollOnce);
        }

        const char *libs[] = {"libandroid_runtime.so", "libart.so", "libc.so"};
        for (const char *lib : libs) {
            hook_lib_symbol(api_, lib, "kill", (void *)my_kill, (void **)&g_orig_kill);
            hook_lib_symbol(api_, lib, "tgkill", (void *)my_tgkill, (void **)&g_orig_tgkill);
            hook_lib_symbol(api_, lib, "__system_property_get", (void *)my_prop_get, (void **)&g_orig_prop_get);
            hook_lib_symbol(api_, lib, "exit", (void *)my_exit, (void **)&g_orig_exit);
            hook_lib_symbol(api_, lib, "_exit", (void *)my__exit, (void **)&g_orig__exit);
            hook_lib_symbol(api_, lib, "exit_group", (void *)my_exit_group, (void **)&g_orig_exit_group);
        }
        bool ok = api_->pltHookCommit();
        LOGI("pltHookCommit=%d kill=%p tgkill=%p prop_get=%p exit=%p exit_group=%p", (int)ok,
             (void *)g_orig_kill, (void *)g_orig_tgkill, (void *)g_orig_prop_get,
             (void *)g_orig_exit, (void *)g_orig_exit_group);
        g_hooks_installed = 1;
    }
};

REGISTER_ZYGISK_MODULE(MztKillModule)

# magisk-mzt-root-hidden

针对 **闽政通（`net.evecom.android.mztapp`）** Root 检测的「反应层」屏蔽模块 —— 一套 Magisk / Zygisk 原生模块 + 一份（历史存档的）LSPosed 模块源码。

> 一句话原理：**不去猜它检测到了什么，直接掐断「检测到 root → 弹窗 → 自杀」这条反应链。**

---

## ⚠️ 免责声明（务必先读）

- 本项目**仅限在你本人拥有的设备上**做技术研究与自用，用于让已经 root 的私人手机不被「检测到 root 就弹窗并杀进程」的行为打断。
- 本项目**不攻击任何服务器、不绕过任何身份认证、不篡改任何业务数据**：它只影响本机进程自身的几个方法调用（`Process.sendSignal` / `kill` / 几个 DEC 判定方法），登录、实人认证、业务校验流程**全部照原样执行**。
- **禁止**将本项目用于欺诈、伪造设备身份、绕过风控从事违法活动，或任何侵犯他人权益、违反当地法律法规与目标应用服务条款的场景。
- 使用本项目的风险（包括但不限于账号被风控、应用功能异常、设备保修失效）由使用者自行承担。作者不对任何后果负责。
- 若你不同意以上任何一条，请立即删除本项目全部文件。

---

## 目录结构

```
magisk-mzt-root-hidden/
├── README.md                  本文件
├── LICENSE                    MIT 协议正文
├── build-zygisk.sh            构建 Zygisk 模块（产出 MztKillModule.zip）
├── build-lsposed.sh           构建 LSPosed 模块（产出 MztRootHide.apk）
├── zygisk-module/             ✅ 实际可用方案
│   ├── module.prop            Magisk 模块描述（id=mztkill, v1.1）
│   ├── service.sh             开机禁用 DEC / 爱加密 弹窗组件
│   ├── uninstall.sh           卸载时恢复被禁用的组件
│   ├── src/mztkill.cpp        原生钩子 + ArtMethod 改写（核心，约 560 行）
│   └── third_party/zygisk/    Zygisk 官方头文件（zygisk.hpp 等，上游原样引用）
└── lsposed-module/            ⚠️ 历史存档，实测不可用（会被壳识别并 SIGSEGV）
    ├── AndroidManifest.xml
    ├── assets/xposed_init
    ├── src/com/mzt/hook/MztHook.java
    └── stubs/                 Xposed API 编译存根（只用于编译，不进 APK）
```

---

## 背景：为什么需要它

闽政通叠加了**四套安全组件**：梆梆 DexHelper 壳 + 梆梆 Everisk 风控（经建行 RiskStub 包装）+ 爱加密 DRisk 环境清场 + DEC 设备环境检测。启动后约 4~8 秒会弹出 `com.a.b.c.DECMsgDialog`：

> 标题：设备已被ROOT
> 正文：检测到您的设备已ROOT，存在隐私信息泄露和被非法攻击等风险！

约 8~10.6 秒后应用自行退出。经内核 kprobe 追踪与 A/B 对照实验确认：**Shamiko + denylist 已经把应用可见的 root 痕迹全部藏住了**（su 路径全部 `ENOENT`、挂载表 0 个 magisk 挂载、maps 里无 shamiko/zygisk/lspd），断网、隐藏 Magisk 应用、卸载管理器均无效 —— 说明触发点在系统调用层看不见的通道，或它检测的是「隐藏行为本身」。

从应用内存里抓到的真实调用链（由 `com.wanjian.cockroach` 防崩溃库留下的堆栈）确定了下手位置：

```
at android.os.Process.sendSignal(Native Method)
at android.os.Process.killProcess(Process.java:1429)
at com.a.b.c.DeviceEnvironmentCheck$1$1.run(DeviceEnvironmentCheck.java:100)   ← 自杀点
at android.app.Activity.runOnUiThread(Activity.java:7771)
at com.a.b.c.DeviceEnvironmentCheck$1.onPostExecute(DeviceEnvironmentCheck.java:95)
at com.a.b.c.DECBackgroundTask$1$1.run(DECBackgroundTask.java:16)
at com.wanjian.cockroach.Cockroach$1.run(Cockroach.java:47)
```

于是思路从「消除判定」转向「掐断反应」。

---

## 为什么最终是 Zygisk 原生模块（而不是 LSPosed）

实测对照（Android 14 / OnePlus PJD110）：

| 注入方式 | 结果 |
|---|---|
| LSPosed 模块**不在**作用域 | 应用正常跑，4~8s 弹窗并退出（原始现象） |
| LSPosed 模块**在**作用域 | 1 秒内 **SIGSEGV 自杀**，模块一行日志都来不及打 |
| Frida（spawn / attach） | 同样 SIGSEGV（`crashsdk/tags/*.signal=11`） |
| Shamiko 白名单模式 | 仍然 SIGSEGV（Shamiko 不隐藏 LSPosed 自身痕迹） |
| **Zygisk 原生模块** | **可稳定存在于应用进程**（Shamiko 就是活例子） |

结论：该壳具备基于 ART 内存特征 / Xposed 痕迹的主动检测并在命中时自杀，LSPosed 与 Frida 两条路被应用自己封死，只剩 Zygisk 原生模块可用。`lsposed-module/` 因此仅作历史存档。

---

## 可用方案做了什么（三件事）

1. **把 DEC 反应方法改成空操作（核心）**
   在 zygote 阶段（`onLoad`）装好 JNI 触发钩子，应用进程一启动就拉起补丁线程，通过应用 `ClassLoader` 加载
   `com.a.b.c.DeviceEnvironmentCheck$1/$1$1`、`DECBackgroundTask$1/$1$1`，用 **ArtMethod 原生改写**
   （`access_flags |= kAccNative`、`data_ = 空实现`、`entry_point = 通用 JNI trampoline`）把
   `run()` / `onPostExecute()` / `doInBackground()` 变成 no-op —— 「关界面 + 自杀」整条反应链不再执行。
   **全程没有 Xposed/LSPosed 痕迹**，壳的注入检测抓不到。

2. **兜底拦自杀**
   替换 `android.os.Process.sendSignal` 的 JNI 实现，并 PLT hook `libandroid_runtime.so` / `libart.so` / `libc.so`
   的 `kill` / `tgkill`（**只拦「对自己发 SIGKILL」**，其它进程的信号一律放行）。

3. **压掉弹窗**
   `service.sh` 开机 `pm disable` 两个弹窗组件（`com.a.b.c.DECMsgDialog`、`com.ijm.detect.drisk.IjiamiActivityOfflineAttack`）；
   运行时改写 `AlertDialog.Builder.show()`，命中「root 风险」文案的警告框不弹，**其它业务对话框照常显示**。

---

## 下载

不想自己编译的话，直接取已发布的成品：

**[Releases → v1.1 · `MztKillModule-v1.1.zip`](https://github.com/yedanten/magisk-mzt-root-hidden/releases/latest)**

- 这是 **Magisk 模块 zip**（不是 APK），模块 ID `mztkill`，version `v1.1` / versionCode `2`，**真机验证可用**。
- 内含 `zygisk/arm64-v8a.so` 的 md5 为 `93cfc1d604f2acc1efc6e6119ec47ae7`，与仓库源码用 `build-zygisk.sh` 重编的产物**逐字节一致**。
- 实验性的 LSPosed 模块（`MztRootHide.apk`）**不提供预编译下载** —— 实测注入会让闽政通在 1 秒内 SIGSEGV，装了就是坏的；确实需要的话请自行用 `build-lsposed.sh` 构建。

---

## 构建

### Zygisk 模块（推荐）

依赖：Android NDK r26d（r25+ 均可）。

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk-r26d
./build-zygisk.sh          # 产出 MztKillModule.zip
```

脚本会依次尝试 `ANDROID_NDK_HOME` → `ANDROID_NDK_ROOT` → `../toolchain/android-ndk-*` → 系统 SDK 目录来定位 NDK。

### LSPosed 模块（历史存档，不发布预编译产物）

> 仓库**不提供**该 APK 的下载：实测它被注入闽政通后应用会立刻 SIGSEGV（见上文对照表），装了只会让应用崩溃。
> 保留源码仅为记录这段弯路，需要复现请自行构建。

依赖：JDK 17 + Android SDK Build-Tools（`d8`/`aapt2`/`zipalign`/`apksigner`）+ `android.jar`（API 34）。

```bash
export JAVA_HOME=/path/to/jdk-17
export BUILD_TOOLS=/path/to/build-tools/34.0.0
export ANDROID_JAR=/path/to/platforms/android-34/android.jar
./build-lsposed.sh         # 产出 MztRootHide.apk
```

---

## 安装与卸载

```bash
# 安装（重启后生效）
adb push MztKillModule.zip /data/local/tmp/
adb shell su -c 'magisk --install-module /data/local/tmp/MztKillModule.zip'
adb reboot

# 卸载（先跑 uninstall.sh 恢复被禁用的弹窗组件，再删模块）
adb shell su -c 'sh /data/adb/modules/mztkill/uninstall.sh'
adb shell su -c 'rm -rf /data/adb/modules/mztkill && reboot'
```

> 注意：`magisk --install-module` 会先把文件放到 `/data/adb/modules_update/`，**必须重启才生效**。

运行时可以在应用 cache 目录看到补丁落地的标记：

```bash
adb shell su -c 'cat /data/data/net.evecom.android.mztapp/cache/mztkill.log'
# patcher-start / patch-thread-start / patched-dialog-show / patched-dec-methods
```

---

## 关键技术坑（复现与维护必读）

1. **不能 hook `android.app.Dialog.show()`**（v1.0 的真实事故）
   v1.0 用 ArtMethod 改写把 `Dialog.show()` 换成 native 桩，再想用 `CallNonvirtualVoidMethod`
   回调备份的 ArtMethod —— **实测回调不生效**，于是全应用所有 `Dialog.show()` 变成空操作：
   `onCreate()` 不跑、布局不加载、窗口不添加。表现为点「获取验证码」「登录」**毫无反应**
   （滑块验证码 `BlockPuzzleDialog` 的 `DragImageView` 为 null → NPE → 被 Cockroach 吞掉）。
   **v1.1 已彻底删除对 `Dialog.show()` 的改写**，只保留 `AlertDialog.Builder.show()` 这一处调用点抑制。
   教训：不要动框架基础设施方法，要在**调用点**或**只读判定**下手。

2. **Zygisk 模块不能动态依赖 `libc++_shared.so`**
   应用进程里没有这个库 → `dlopen` 失败，Magisk 会在模块目录写 `zygisk/unloaded` 标记。
   必须 `-static-libstdc++` 静态链接。

3. **进程名在 specialize 期间是 `<pre-initialized>`**
   按进程名判断「是不是目标进程」时若把它缓存下来，应用进程会永久把自己判成「非目标」而失效。
   必须对 `zygote*` / `<pre-initialized>` / 空名**不缓存**。

4. **主进程走 USAP 路径**
   Zygisk 的 `preAppSpecialize` / `postAppSpecialize` 回调只在 `:push` / `:tools` 这类进程触发，
   主进程拿不到回调 → 钩子必须放在 `onLoad`（zygote 阶段）装好、由 fork 继承。
   触发点要用主线程**必然调用**的 `MessageQueue.nativePollOnce`
   （`SystemProperties.native_get` 在 specialize 之后不一定会被应用调到，实测会漏触发）。

---

## 验证结果（真机，Android 14 / OnePlus PJD110）

- 冷启动多次、连续观察 60s+、切页交互，**主进程均存活，不再自杀**。
- 界面可用：进入「首页」「我的」页面正常渲染。
- 「获取验证码」短信真的下发并自动回填（6 位码出现、按钮变「倒计时 XXs」）；「登录」可正常弹出应用自身的
  「选择内容类型」对话框并走到实人认证页 —— 即 **v1.0 的「登录无反应」已修复**。
- 在 **denylist + Shamiko 黑名单模式**（原始配置）下同样生效，无需改动任何隐藏配置。

---

## 局限

- 本方案是**掐反应**而不是**消除判定**：SDK 内部仍可能把「环境异常」上报到服务端，**账号风控层面需自行评估**。
- 弹窗里那个可点击「好的」关闭的警告框（`AlertDialog`，文案「当前APP运行环境（root）存在风险…」）
  由 `Builder.show()` 文案匹配抑制，若该壳改文案则需同步更新匹配规则。
- 若目标应用升级加固方案，本项目的 ArtMethod 偏移（Android 11~14，64 位 + 压缩引用）与类名清单可能失效。

---

## 开源协议与开发工具

### 本项目：MIT License

本项目以 **MIT 协议**开源，全文见 [LICENSE](LICENSE)，Copyright (c) 2026 yedanten。
要点：允许自由使用、复制、修改、合并、发布、分发、再许可和/或销售软件副本；
唯一要求是保留版权声明与许可声明；软件按「原样」提供，不含任何明示或暗示的担保。

### 开发工具：DSH（DeepSeek Harness）协议

本项目的分析、逆向、编码、构建与文档**全程由 DSH（DeepSeek Harness）驱动完成**。
DSH 自身同样以 **MIT License** 发布，Copyright (c) 2026 DeepSeek，其协议要点与上文 MIT 条款一致：
允许自由使用、复制、修改、合并、发布、分发、再许可和/或销售，需保留版权与许可声明，软件按「原样」提供、不附带任何担保。

### 第三方组件

- `zygisk-module/third_party/zygisk/` 下的 Zygisk 头文件来自
  [topjohnwu/zygisk-module-sample](https://github.com/topjohnwu/zygisk-module-sample)，
  Copyright 2022-2023 John "topjohnwu" Wu，采用宽松的 0BSD 风格许可
  （Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted），
  原文保留在各文件头部。

---

## 纯 AI Vibecoding 声明

**本项目 100% 由 AI 完成 —— 纯 AI Vibecoding。**

- 全部源代码、构建脚本、技术路线与本文档均由 AI（DSH / DeepSeek Harness）生成。
- 逆向分析、动态追踪、实验设计、真机验证与排障（含 v1.0 → v1.1 的事故定位）同样由 AI 主导完成。
- 人类使用者只负责提供设备、执行指令、反馈现象与做决策选择。
- 因此：代码风格可能跳脱，注释比代码还多，欢迎 issue / PR 指正。

> Powered by **DSH — DeepSeek Harness** 🛠️

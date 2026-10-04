package com.mzt.hook;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 闽政通 root 检测"反应层"屏蔽模块。
 *
 * 设计依据（从应用内存里抓到的真实调用链，经 Cockroach 崩溃兜底记录）：
 *   at android.os.Process.sendSignal(Native Method)
 *   at android.os.Process.killProcess(Process.java:1429)
 *   at com.a.b.c.DeviceEnvironmentCheck$1$1.run(DeviceEnvironmentCheck.java:100)
 *   at android.app.Activity.runOnUiThread(Activity.java:7771)
 *   at com.a.b.c.DeviceEnvironmentCheck$1.onPostExecute(DeviceEnvironmentCheck.java:95)
 *   at com.a.b.c.DeviceEnvironmentCheck$1.onPostExecute(DeviceEnvironmentCheck.java:80)
 *   at com.a.b.c.DECBackgroundTask$1$1.run(DECBackgroundTask.java:16)
 *
 * 策略：不去猜它"检测到了什么"，直接掐断"弹窗 + 自杀"这条反应链：
 *   1) killProcess / sendSignal / System.exit / Runtime.halt 一律拦掉（多套 SDK 都会杀进程）
 *   2) 拦截以 com.a.b.c.* / Ijiami* 为目标的 Activity 启动，DECMsgDialog 永不出现
 *   3) 对 DEC 判定类的布尔/数值方法强制返回"无风险"，让 SDK 内部结论也是干净的
 *   4) 顺手隐藏 Xposed/LSPosed 类痕迹，避免"因为装了模块反而被判 hook"
 */
public class MztHook implements IXposedHookLoadPackage {

    private static final String TAG = "MztHook";
    private static final String PKG = "net.evecom.android.mztapp";

    /** 需要"压掉反应"的判定类（DEC = com.a.b.c.*） */
    private static final String[] DEC_CLASSES = new String[]{
            "com.a.b.c.DeviceEnvironmentCheck",
            "com.a.b.c.DeviceEnvironmentCheck$1",
            "com.a.b.c.DeviceEnvironmentCheck$1$1",
            "com.a.b.c.DeviceEnvironmentCheck$2",
            "com.a.b.c.DeviceEnvironmentCheck$2$1",
            "com.a.b.c.DECBackgroundTask",
            "com.a.b.c.DECBackgroundTask$1",
            "com.a.b.c.DECBackgroundTask$1$1",
            "com.a.b.c.DECRunning"
    };

    /** 需要直接压掉的 Activity（弹窗） */
    private static final String[] BLOCK_ACTIVITIES = new String[]{
            "com.a.b.c.DECMsgDialog",
            "com.ijm.detect.drisk.IjiamiActivityOfflineAttack"
    };

    private static final String[] RISK_METHOD_NAMES = new String[]{
            "run", "onPostExecute", "doInBackground", "onPreExecute", "onProgressUpdate", "call"
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) throws Throwable {
        if (lp == null || !PKG.equals(lp.packageName)) {
            return;
        }
        log("inject ok: pkg=" + lp.packageName + " proc=" + lp.processName);
        hookSuicide(lp.classLoader);
        hookDialogs(lp.classLoader);
        hookDecVerdict(lp.classLoader);
        hideXposed(lp.classLoader);
        log("all hooks installed");
    }

    // ---------------------------------------------------------------- 1. 自杀链

    private void hookSuicide(final ClassLoader cl) {
        // android.os.Process.killProcess(int)
        try {
            XposedHelpers.findAndHookMethod(Process.class.getName(), cl, "killProcess", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("BLOCK killProcess(" + param.args[0] + ")  caller=" + where());
                            param.setResult(null);
                        }
                    });
        } catch (Throwable t) {
            log("hook killProcess fail: " + t);
        }

        // android.os.Process.sendSignal(int,int)
        try {
            XposedHelpers.findAndHookMethod(Process.class.getName(), cl, "sendSignal", int.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("BLOCK sendSignal(" + param.args[0] + "," + param.args[1] + ")  caller=" + where());
                            param.setResult(null);
                        }
                    });
        } catch (Throwable t) {
            log("hook sendSignal fail: " + t);
        }

        // System.exit(int)
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", cl, "exit", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("BLOCK System.exit(" + param.args[0] + ")  caller=" + where());
                            param.setResult(null);
                        }
                    });
        } catch (Throwable t) {
            log("hook System.exit fail: " + t);
        }

        // Runtime.halt(int)
        try {
            XposedHelpers.findAndHookMethod("java.lang.Runtime", cl, "halt", int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            log("BLOCK Runtime.halt(" + param.args[0] + ")  caller=" + where());
                            param.setResult(null);
                        }
                    });
        } catch (Throwable t) {
            log("hook Runtime.halt fail: " + t);
        }
    }

    // ---------------------------------------------------------------- 2. 弹窗

    private void hookDialogs(final ClassLoader cl) {
        final XC_MethodHook blockStart = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length == 0 || !(param.args[0] instanceof Intent)) {
                    return;
                }
                Intent it = (Intent) param.args[0];
                String cn = null;
                try {
                    cn = it.getComponent() != null ? it.getComponent().getClassName() : null;
                } catch (Throwable ignored) {
                }
                if (cn != null && isBlockedActivity(cn)) {
                    log("BLOCK startActivity -> " + cn);
                    param.setResult(null);
                }
            }
        };

        String[][] targets = new String[][]{
                {"android.content.ContextWrapper", "startActivity"},
                {"android.app.Activity", "startActivity"},
                {"android.content.ContextWrapper", "startActivityForResult"},
                {"android.app.Activity", "startActivityForResult"},
                {"android.app.Activity", "startActivityIfNeeded"},
        };
        for (String[] t : targets) {
            try {
                XposedHelpers.findAndHookMethod(t[0], cl, t[1], Intent.class, int.class, blockStart);
            } catch (Throwable ignored) {
            }
            try {
                XposedHelpers.findAndHookMethod(t[0], cl, t[1], Intent.class, blockStart);
            } catch (Throwable ignored) {
            }
            try {
                XposedHelpers.findAndHookMethod(t[0], cl, t[1], Intent.class, int.class, Bundle.class, blockStart);
            } catch (Throwable ignored) {
            }
        }
        log("dialog blockers installed");

        // 万一还是被拉起来了：onCreate 后立刻 finish，避免挡住用户
        for (final String cn : BLOCK_ACTIVITIES) {
            try {
                XposedHelpers.findAndHookMethod(cn, cl, "onCreate", Bundle.class, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        log("suppress " + cn + ".onCreate -> finish()");
                        try {
                            ((Activity) param.thisObject).finish();
                        } catch (Throwable ignored) {
                        }
                    }
                });
            } catch (Throwable ignored) {
            }
        }
    }

    private static boolean isBlockedActivity(String className) {
        if (className == null) {
            return false;
        }
        if (className.startsWith("com.a.b.c.")) {
            return true;
        }
        String l = className.toLowerCase();
        return l.contains("ijiami") || l.contains("offlineattack") || l.contains("drisk")
                || l.contains("riskstub") || l.contains("everisk");
    }

    // ---------------------------------------------------------------- 3. 判定结论

    private void hookDecVerdict(final ClassLoader cl) {
        for (String cn : DEC_CLASSES) {
            Class<?> c;
            try {
                c = XposedHelpers.findClass(cn, cl);
            } catch (Throwable t) {
                continue;
            }
            Method[] ms;
            try {
                ms = c.getDeclaredMethods();
            } catch (Throwable t) {
                continue;
            }
            int hooked = 0;
            for (Method m : ms) {
                if (Modifier.isAbstract(m.getModifiers()) || Modifier.isNative(m.getModifiers())) {
                    continue;
                }
                Class<?> rt = m.getReturnType();
                String mn = m.getName();
                try {
                    if (isRiskStep(mn)) {
                        // 反应链上的方法：直接跳过原实现
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                Class<?> rt = (param.method instanceof Method)
                                        ? ((Method) param.method).getReturnType() : void.class;
                                log("SKIP " + param.method.getName() + "() (declared by "
                                        + param.method.getDeclaringClass().getName() + ")");
                                param.setResult(defaultValue(rt));
                            }
                        });
                        hooked++;
                    } else if (rt == boolean.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                Object r = param.getResult();
                                if (r instanceof Boolean && ((Boolean) r)) {
                                    log("FORCE " + param.method.getName() + "(): true -> false");
                                    param.setResult(Boolean.FALSE);
                                }
                            }
                        });
                        hooked++;
                    } else if (rt == int.class || rt == long.class) {
                        XposedBridge.hookMethod(m, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                Object r = param.getResult();
                                if (r instanceof Integer && ((Integer) r) != 0) {
                                    log("FORCE " + param.method.getName() + "(): " + r + " -> 0");
                                    param.setResult(0);
                                } else if (r instanceof Long && ((Long) r) != 0L) {
                                    log("FORCE " + param.method.getName() + "(): " + r + " -> 0");
                                    param.setResult(0L);
                                }
                            }
                        });
                        hooked++;
                    }
                } catch (Throwable ignored) {
                }
            }
            log("hooked " + cn + " (" + hooked + " methods)");
        }
    }

    private static boolean isRiskStep(String name) {
        for (String n : RISK_METHOD_NAMES) {
            if (n.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static Object defaultValue(Class<?> rt) {
        if (rt == boolean.class) return Boolean.FALSE;
        if (rt == int.class) return 0;
        if (rt == long.class) return 0L;
        if (rt == short.class) return (short) 0;
        if (rt == byte.class) return (byte) 0;
        if (rt == char.class) return (char) 0;
        if (rt == float.class) return 0f;
        if (rt == double.class) return 0d;
        return null;
    }

    // ---------------------------------------------------------------- 4. 反-反 hook

    private void hideXposed(final ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod("java.lang.Class", cl, "forName", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            String n = (String) param.args[0];
                            if (isFrameworkClass(n)) {
                                log("HIDE Class.forName(" + n + ")");
                                throw new ClassNotFoundException(n);
                            }
                        }
                    });
        } catch (Throwable t) {
            log("hide Class.forName fail: " + t);
        }
        try {
            XposedHelpers.findAndHookMethod("java.lang.ClassLoader", cl, "loadClass", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            String n = (String) param.args[0];
                            if (isFrameworkClass(n)) {
                                log("HIDE ClassLoader.loadClass(" + n + ")");
                                throw new ClassNotFoundException(n);
                            }
                        }
                    });
        } catch (Throwable t) {
            log("hide ClassLoader.loadClass fail: " + t);
        }
    }

    private static boolean isFrameworkClass(String n) {
        if (n == null) {
            return false;
        }
        return n.startsWith("de.robv.android.xposed.")
                || n.startsWith("org.lsposed.")
                || n.contains("XposedBridge")
                || n.contains("XposedHelpers");
    }

    // ---------------------------------------------------------------- utils

    private static void log(String s) {
        Log.i(TAG, s);
        try {
            XposedBridge.log(TAG + ": " + s);
        } catch (Throwable ignored) {
        }
    }

    private static String where() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (StackTraceElement e : st) {
            String s = e.toString();
            if (s.contains("MztHook")) {
                continue;
            }
            if (n > 0) {
                sb.append(" <- ");
            }
            sb.append(s);
            if (++n >= 6) {
                break;
            }
        }
        return sb.toString();
    }
}

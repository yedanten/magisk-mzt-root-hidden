package de.robv.android.xposed;

import java.lang.reflect.Member;

/** 仅用于编译的 Xposed API 存根。 */
public final class XposedBridge {

    private XposedBridge() {
    }

    public static void log(String text) {
    }

    public static void log(Throwable t) {
    }

    public static XC_MethodHook.Unhook hookMethod(Member method, XC_MethodHook callback) {
        return null;
    }
}

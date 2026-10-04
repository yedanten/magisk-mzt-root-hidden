package de.robv.android.xposed;

import java.lang.reflect.Member;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** 仅用于编译的 Xposed API 存根。 */
public interface IXposedHookLoadPackage {
    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;
}

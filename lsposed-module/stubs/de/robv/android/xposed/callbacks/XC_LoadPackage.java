package de.robv.android.xposed.callbacks;

import android.content.pm.ApplicationInfo;

/** 仅用于编译的 Xposed API 存根。 */
public abstract class XC_LoadPackage extends XCallback {

    public static class LoadPackageParam extends XCallback.Param {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }

    public XC_LoadPackage() {
    }
}

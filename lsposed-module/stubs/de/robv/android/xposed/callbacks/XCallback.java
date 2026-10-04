package de.robv.android.xposed.callbacks;

/** 仅用于编译的 Xposed API 存根（不会打进模块 dex）。 */
public abstract class XCallback implements Comparable<XCallback> {

    public abstract static class Param {
        public XCallback callbacks;
    }

    @Override
    public int compareTo(XCallback other) {
        return 0;
    }
}

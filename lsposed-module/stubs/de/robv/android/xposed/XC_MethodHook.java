package de.robv.android.xposed;

import java.lang.reflect.Member;

import de.robv.android.xposed.callbacks.XCallback;

/** 仅用于编译的 Xposed API 存根。 */
public abstract class XC_MethodHook {

    public XC_MethodHook() {
    }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    }

    public static class MethodHookParam extends XCallback.Param {
        public Member method;
        public Object thisObject;
        public Object[] args;
        private Object result = null;
        private Throwable throwable = null;

        public Object getResult() {
            return result;
        }

        public void setResult(Object result) {
            this.result = result;
            this.throwable = null;
        }

        public Throwable getThrowable() {
            return throwable;
        }

        public void setThrowable(Throwable throwable) {
            this.throwable = throwable;
            this.result = null;
        }

        public boolean hasThrowable() {
            return throwable != null;
        }

        public Object getResultOrThrowable() throws Throwable {
            if (throwable != null) {
                throw throwable;
            }
            return result;
        }
    }

    public class Unhook {
        public Member getHookedMethod() {
            return null;
        }

        public void unhook() {
        }
    }
}

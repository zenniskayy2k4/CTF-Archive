package android.support.v4.os;

import android.os.Handler;

/* loaded from: classes.dex */
public final class HandlerCompat {
    public static boolean postDelayed(Handler handler, Runnable runnable, Object obj, long j) {
        return handler.postDelayed(runnable, obj, j);
    }

    private HandlerCompat() {
    }
}

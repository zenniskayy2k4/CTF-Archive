package android.support.v4.view;

import android.graphics.Rect;
import android.view.DisplayCutout;
import java.util.List;

/* loaded from: classes.dex */
public final class DisplayCutoutCompat {
    private final Object mDisplayCutout;

    public DisplayCutoutCompat(Rect rect, List<Rect> list) {
        this(new DisplayCutout(rect, list));
    }

    private DisplayCutoutCompat(Object obj) {
        this.mDisplayCutout = obj;
    }

    public int getSafeInsetTop() {
        return ((DisplayCutout) this.mDisplayCutout).getSafeInsetTop();
    }

    public int getSafeInsetBottom() {
        return ((DisplayCutout) this.mDisplayCutout).getSafeInsetBottom();
    }

    public int getSafeInsetLeft() {
        return ((DisplayCutout) this.mDisplayCutout).getSafeInsetLeft();
    }

    public int getSafeInsetRight() {
        return ((DisplayCutout) this.mDisplayCutout).getSafeInsetRight();
    }

    public List<Rect> getBoundingRects() {
        return ((DisplayCutout) this.mDisplayCutout).getBoundingRects();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Object obj2 = this.mDisplayCutout;
        Object obj3 = ((DisplayCutoutCompat) obj).mDisplayCutout;
        if (obj2 == null) {
            return obj3 == null;
        }
        return obj2.equals(obj3);
    }

    public int hashCode() {
        Object obj = this.mDisplayCutout;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public String toString() {
        return "DisplayCutoutCompat{" + this.mDisplayCutout + "}";
    }

    static DisplayCutoutCompat wrap(Object obj) {
        if (obj == null) {
            return null;
        }
        return new DisplayCutoutCompat(obj);
    }
}

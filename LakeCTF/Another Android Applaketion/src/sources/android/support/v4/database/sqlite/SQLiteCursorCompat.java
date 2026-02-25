package android.support.v4.database.sqlite;

import android.database.sqlite.SQLiteCursor;

/* loaded from: classes.dex */
public final class SQLiteCursorCompat {
    private SQLiteCursorCompat() {
    }

    public static void setFillWindowForwardOnly(SQLiteCursor sQLiteCursor, boolean z) {
        sQLiteCursor.setFillWindowForwardOnly(z);
    }
}

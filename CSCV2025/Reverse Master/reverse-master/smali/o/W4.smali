.class public final Lo/W4;
.super Lo/W2;
.source "SourceFile"


# instance fields
.field public final c:Z


# direct methods
.method public constructor <init>()V
    .locals 6

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Lo/W2;-><init>(Z)V

    const/4 v1, 0x0

    invoke-virtual {p0, v1}, Lo/W2;->s(Lo/O2;)V

    sget-object v2, Lo/W2;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lo/Z;

    instance-of v4, v3, Lo/a0;

    if-eqz v4, :cond_0

    check-cast v3, Lo/a0;

    goto :goto_0

    :cond_0
    move-object v3, v1

    :goto_0
    const/4 v4, 0x0

    if-eqz v3, :cond_3

    invoke-virtual {v3}, Lo/S2;->j()Lo/W2;

    move-result-object v3

    :goto_1
    invoke-virtual {v3}, Lo/W2;->n()Z

    move-result v5

    if-eqz v5, :cond_1

    goto :goto_3

    :cond_1
    invoke-virtual {v2, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lo/Z;

    instance-of v5, v3, Lo/a0;

    if-eqz v5, :cond_2

    check-cast v3, Lo/a0;

    goto :goto_2

    :cond_2
    move-object v3, v1

    :goto_2
    if-eqz v3, :cond_3

    invoke-virtual {v3}, Lo/S2;->j()Lo/W2;

    move-result-object v3

    goto :goto_1

    :cond_3
    move v0, v4

    :goto_3
    iput-boolean v0, p0, Lo/W4;->c:Z

    return-void
.end method


# virtual methods
.method public final i(Ljava/lang/Throwable;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final n()Z
    .locals 1

    iget-boolean v0, p0, Lo/W4;->c:Z

    return v0
.end method

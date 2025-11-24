.class public abstract Lo/c;
.super Lo/W2;
.source "SourceFile"

# interfaces
.implements Lo/B0;
.implements Lo/P0;


# instance fields
.field public final c:Lo/H0;


# direct methods
.method public constructor <init>(Lo/H0;Z)V
    .locals 0

    invoke-direct {p0, p2}, Lo/W2;-><init>(Z)V

    sget-object p2, Lo/D0;->c:Lo/D0;

    invoke-interface {p1, p2}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object p2

    check-cast p2, Lo/O2;

    invoke-virtual {p0, p2}, Lo/W2;->s(Lo/O2;)V

    invoke-interface {p1, p0}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p1

    iput-object p1, p0, Lo/c;->c:Lo/H0;

    return-void
.end method


# virtual methods
.method public final getContext()Lo/H0;
    .locals 1

    iget-object v0, p0, Lo/c;->c:Lo/H0;

    return-object v0
.end method

.method public final getCoroutineContext()Lo/H0;
    .locals 1

    iget-object v0, p0, Lo/c;->c:Lo/H0;

    return-object v0
.end method

.method public final h()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    const-string v1, " was cancelled"

    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final r(Lo/s0;)V
    .locals 1

    iget-object v0, p0, Lo/c;->c:Lo/H0;

    invoke-static {v0, p1}, Lo/F2;->k(Lo/H0;Ljava/lang/Throwable;)V

    return-void
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 2

    invoke-static {p1}, Lo/t4;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Lo/q0;

    const/4 v1, 0x0

    invoke-direct {p1, v1, v0}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    :goto_0
    invoke-virtual {p0, p1}, Lo/W2;->v(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Lo/F2;->c:Lo/Q;

    if-ne p1, v0, :cond_1

    return-void

    :cond_1
    invoke-virtual {p0, p1}, Lo/c;->e(Ljava/lang/Object;)V

    return-void
.end method

.method public final y(Ljava/lang/Object;)V
    .locals 1

    instance-of v0, p1, Lo/q0;

    if-eqz v0, :cond_0

    check-cast p1, Lo/q0;

    iget-object v0, p1, Lo/q0;->a:Ljava/lang/Throwable;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Lo/q0;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    :cond_0
    return-void
.end method

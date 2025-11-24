.class public abstract Lo/G4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Lo/Q;

.field public static final b:Lo/Q;

.field public static final c:Lo/Q;

.field public static final d:Lo/Q;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    new-instance v0, Lo/Q;

    const-string v1, "UNDEFINED"

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/G4;->a:Lo/Q;

    new-instance v0, Lo/Q;

    const-string v1, "REUSABLE_CLAIMED"

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/G4;->b:Lo/Q;

    new-instance v0, Lo/Q;

    const-string v1, "CONDITION_FALSE"

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/G4;->c:Lo/Q;

    new-instance v0, Lo/Q;

    const-string v1, "NO_THREAD_ELEMENTS"

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/G4;->d:Lo/Q;

    return-void
.end method

.method public static final a(Landroidx/core/os/c;Lo/C0;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p1, Lo/b4;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Lo/b4;

    iget v1, v0, Lo/b4;->c:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Lo/b4;->c:I

    goto :goto_0

    :cond_0
    new-instance v0, Lo/b4;

    invoke-direct {v0, p1}, Lo/C0;-><init>(Lo/B0;)V

    :goto_0
    iget-object p1, v0, Lo/b4;->b:Ljava/lang/Object;

    iget v1, v0, Lo/b4;->c:I

    const/4 v2, 0x1

    if-eqz v1, :cond_2

    if-ne v1, v2, :cond_1

    iget-object p0, v0, Lo/b4;->a:Lo/H1;

    :try_start_0
    invoke-static {p1}, Lo/F2;->q(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {p0}, Lo/H1;->invoke()Ljava/lang/Object;

    sget-object p0, Lo/p5;->a:Lo/p5;

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p1}, Lo/F2;->q(Ljava/lang/Object;)V

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object p1

    sget-object v1, Lo/D0;->c:Lo/D0;

    invoke-interface {p1, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object p1

    if-nez p1, :cond_3

    :try_start_1
    iput-object p0, v0, Lo/b4;->a:Lo/H1;

    iput v2, v0, Lo/b4;->c:I

    new-instance p1, Lo/U;

    invoke-static {v0}, Lo/F2;->l(Lo/B0;)Lo/B0;

    move-result-object v0

    invoke-direct {p1, v0}, Lo/U;-><init>(Lo/B0;)V

    invoke-virtual {p1}, Lo/U;->k()V

    const/4 p1, 0x0

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_1
    invoke-interface {p0}, Lo/H1;->invoke()Ljava/lang/Object;

    throw p1

    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "awaitClose() can only be invoked from the producer context"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static b(Ljava/lang/Object;)V
    .locals 2

    if-eqz p0, :cond_6

    instance-of v0, p0, Lo/e2;

    if-eqz v0, :cond_5

    instance-of v0, p0, Lo/g2;

    const/4 v1, 0x2

    if-eqz v0, :cond_0

    move-object v0, p0

    check-cast v0, Lo/g2;

    invoke-interface {v0}, Lo/g2;->getArity()I

    move-result v0

    goto :goto_0

    :cond_0
    instance-of v0, p0, Lo/H1;

    if-eqz v0, :cond_1

    const/4 v0, 0x0

    goto :goto_0

    :cond_1
    instance-of v0, p0, Lo/S1;

    if-eqz v0, :cond_2

    const/4 v0, 0x1

    goto :goto_0

    :cond_2
    instance-of v0, p0, Lo/W1;

    if-eqz v0, :cond_3

    move v0, v1

    goto :goto_0

    :cond_3
    instance-of v0, p0, Lo/Y1;

    if-eqz v0, :cond_4

    const/4 v0, 0x4

    goto :goto_0

    :cond_4
    const/4 v0, -0x1

    :goto_0
    if-ne v0, v1, :cond_5

    goto :goto_1

    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    const-string v0, " cannot be cast to kotlin.jvm.functions.Function2"

    invoke-virtual {p0, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0, p0}, Ljava/lang/ClassCastException;-><init>(Ljava/lang/String;)V

    const-class p0, Lo/G4;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-static {v0, p0}, Lo/F2;->p(Ljava/lang/RuntimeException;Ljava/lang/String;)V

    throw v0

    :cond_6
    :goto_1
    return-void
.end method

.method public static c(Lo/O2;)V
    .locals 3

    check-cast p0, Lo/W2;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Lo/P2;

    invoke-virtual {p0}, Lo/W2;->h()Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2, p0}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    invoke-virtual {p0, v0}, Lo/W2;->f(Ljava/lang/Object;)Z

    return-void
.end method

.method public static final d(I)V
    .locals 1

    const/4 v0, 0x1

    if-lt p0, v0, :cond_0

    return-void

    :cond_0
    const-string v0, "Expected positive parallelism level, but got "

    invoke-static {v0, p0}, Lo/l;->d(Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final e(Lo/H0;Lo/H0;Z)Lo/H0;
    .locals 4

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    sget-object v0, Lo/m0;->e:Lo/m0;

    invoke-interface {p0, p2, v0}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    invoke-interface {p1, p2, v0}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-nez v1, :cond_0

    if-nez p2, :cond_0

    invoke-interface {p0, p1}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p0

    return-object p0

    :cond_0
    sget-object v0, Lo/p1;->a:Lo/p1;

    new-instance v1, Lo/m0;

    const/4 v2, 0x2

    const/4 v3, 0x7

    invoke-direct {v1, v2, v3}, Lo/m0;-><init>(II)V

    invoke-interface {p0, v0, v1}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lo/H0;

    if-eqz p2, :cond_1

    check-cast p1, Lo/H0;

    sget-object p2, Lo/m0;->d:Lo/m0;

    invoke-interface {p1, v0, p2}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p1

    :cond_1
    check-cast p1, Lo/H0;

    invoke-interface {p0, p1}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p0

    return-object p0
.end method

.method public static f(Lo/W1;)Lo/D4;
    .locals 1

    new-instance v0, Lo/D4;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    invoke-static {v0, v0, p0}, Lo/F2;->g(Lo/B0;Lo/B0;Lo/W1;)Lo/B0;

    move-result-object p0

    iput-object p0, v0, Lo/D4;->d:Lo/B0;

    return-object v0
.end method

.method public static g(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/n2;Lo/W1;I)Lo/M4;
    .locals 2

    const/4 v0, 0x1

    and-int/2addr p3, v0

    if-eqz p3, :cond_0

    sget-object p1, Lo/p1;->a:Lo/p1;

    :cond_0
    sget-object p3, Lo/S0;->a:Lo/S0;

    invoke-interface {p0}, Lo/P0;->getCoroutineContext()Lo/H0;

    move-result-object p0

    invoke-static {p0, p1, v0}, Lo/G4;->e(Lo/H0;Lo/H0;Z)Lo/H0;

    move-result-object p0

    sget-object p1, Lo/j1;->a:Lo/b1;

    if-eq p0, p1, :cond_1

    sget-object v1, Lo/D0;->a:Lo/D0;

    invoke-interface {p0, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-interface {p0, p1}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p0

    :cond_1
    new-instance p1, Lo/M4;

    invoke-direct {p1, p0, v0}, Lo/c;-><init>(Lo/H0;Z)V

    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_5

    if-eq p0, v0, :cond_4

    const/4 p3, 0x2

    if-eq p0, p3, :cond_3

    const/4 p3, 0x3

    if-ne p0, p3, :cond_2

    :try_start_0
    iget-object p0, p1, Lo/c;->c:Lo/H0;

    const/4 p3, 0x0

    invoke-static {p0, p3}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    invoke-static {p2}, Lo/G4;->b(Ljava/lang/Object;)V

    invoke-interface {p2, p1, p1}, Lo/W1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-static {p0, p3}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    sget-object p0, Lo/Q0;->a:Lo/Q0;

    if-eq p2, p0, :cond_4

    invoke-virtual {p1, p2}, Lo/c;->resumeWith(Ljava/lang/Object;)V

    return-object p1

    :catchall_0
    move-exception p0

    goto :goto_0

    :catchall_1
    move-exception p2

    :try_start_3
    invoke-static {p0, p3}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    throw p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_0
    invoke-static {p0}, Lo/F2;->h(Ljava/lang/Throwable;)Lo/s4;

    move-result-object p0

    invoke-virtual {p1, p0}, Lo/c;->resumeWith(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    new-instance p0, Lo/s0;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_3
    invoke-static {p1, p1, p2}, Lo/F2;->g(Lo/B0;Lo/B0;Lo/W1;)Lo/B0;

    move-result-object p0

    invoke-static {p0}, Lo/F2;->l(Lo/B0;)Lo/B0;

    move-result-object p0

    sget-object p2, Lo/p5;->a:Lo/p5;

    invoke-interface {p0, p2}, Lo/B0;->resumeWith(Ljava/lang/Object;)V

    :cond_4
    :goto_1
    return-object p1

    :cond_5
    invoke-static {p2, p1, p1}, Lo/W0;->h(Lo/W1;Lo/c;Lo/c;)V

    return-object p1
.end method

.method public static final h(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    instance-of v0, p0, Lo/q0;

    if-eqz v0, :cond_0

    check-cast p0, Lo/q0;

    iget-object p0, p0, Lo/q0;->a:Ljava/lang/Throwable;

    invoke-static {p0}, Lo/F2;->h(Ljava/lang/Throwable;)Lo/s4;

    move-result-object p0

    :cond_0
    return-object p0
.end method

.method public static final i(Lo/H0;Ljava/lang/Object;)V
    .locals 2

    sget-object v0, Lo/G4;->d:Lo/Q;

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Lo/h5;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    check-cast p1, Lo/h5;

    iget-object p0, p1, Lo/h5;->b:[Lo/e5;

    array-length v0, p0

    add-int/lit8 v0, v0, -0x1

    if-gez v0, :cond_1

    :goto_0
    return-void

    :cond_1
    aget-object p0, p0, v0

    invoke-static {v1}, Lo/F2;->c(Ljava/lang/Object;)V

    iget-object p0, p1, Lo/h5;->a:[Ljava/lang/Object;

    aget-object p0, p0, v0

    throw v1

    :cond_2
    sget-object p1, Lo/m0;->g:Lo/m0;

    invoke-interface {p0, v1, p1}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p0

    const-string p1, "null cannot be cast to non-null type kotlinx.coroutines.ThreadContextElement<kotlin.Any?>"

    invoke-static {p0, p1}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Lo/l;->r(Ljava/lang/Object;)V

    throw v1
.end method

.method public static final j(Lo/U;Lo/B0;Z)V
    .locals 2

    sget-object v0, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0, v0}, Lo/U;->c(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-static {v1}, Lo/F2;->h(Ljava/lang/Throwable;)Lo/s4;

    move-result-object p0

    goto :goto_0

    :cond_0
    invoke-virtual {p0, v0}, Lo/U;->d(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    :goto_0
    if-eqz p2, :cond_6

    const-string p2, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTaskKt.resume>"

    invoke-static {p1, p2}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Lo/g1;

    iget-object p2, p1, Lo/g1;->e:Lo/B0;

    invoke-interface {p2}, Lo/B0;->getContext()Lo/H0;

    move-result-object v0

    iget-object p1, p1, Lo/g1;->g:Ljava/lang/Object;

    invoke-static {v0, p1}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v1, Lo/G4;->d:Lo/Q;

    if-eq p1, v1, :cond_1

    invoke-static {p2, v0, p1}, Lo/G4;->o(Lo/B0;Lo/H0;Ljava/lang/Object;)Lo/n5;

    move-result-object v1

    goto :goto_1

    :cond_1
    const/4 v1, 0x0

    :goto_1
    :try_start_0
    invoke-interface {p2, p0}, Lo/B0;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_3

    invoke-virtual {v1}, Lo/n5;->D()Z

    move-result p0

    if-eqz p0, :cond_2

    goto :goto_2

    :cond_2
    return-void

    :cond_3
    :goto_2
    invoke-static {v0, p1}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception p0

    if-eqz v1, :cond_4

    invoke-virtual {v1}, Lo/n5;->D()Z

    move-result p2

    if-eqz p2, :cond_5

    :cond_4
    invoke-static {v0, p1}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    :cond_5
    throw p0

    :cond_6
    invoke-interface {p1, p0}, Lo/B0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public static final k(Ljava/lang/Object;Lo/B0;)V
    .locals 9

    instance-of v0, p1, Lo/g1;

    if-eqz v0, :cond_a

    check-cast p1, Lo/g1;

    invoke-static {p0}, Lo/t4;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_0

    move-object v1, p0

    goto :goto_0

    :cond_0
    new-instance v1, Lo/q0;

    const/4 v2, 0x0

    invoke-direct {v1, v2, v0}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    :goto_0
    iget-object v0, p1, Lo/g1;->e:Lo/B0;

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v2

    iget-object v3, p1, Lo/g1;->d:Lo/K0;

    invoke-virtual {v3, v2}, Lo/K0;->isDispatchNeeded(Lo/H0;)Z

    move-result v2

    const/4 v4, 0x1

    if-eqz v2, :cond_1

    iput-object v1, p1, Lo/g1;->f:Ljava/lang/Object;

    iput v4, p1, Lo/i1;->c:I

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object p0

    invoke-virtual {v3, p0, p1}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void

    :cond_1
    invoke-static {}, Lo/f5;->a()Lo/x1;

    move-result-object v2

    iget-wide v5, v2, Lo/x1;->a:J

    const-wide v7, 0x100000000L

    cmp-long v3, v5, v7

    if-ltz v3, :cond_3

    iput-object v1, p1, Lo/g1;->f:Ljava/lang/Object;

    iput v4, p1, Lo/i1;->c:I

    iget-object p0, v2, Lo/x1;->c:Lo/G;

    if-nez p0, :cond_2

    new-instance p0, Lo/G;

    invoke-direct {p0}, Lo/G;-><init>()V

    iput-object p0, v2, Lo/x1;->c:Lo/G;

    :cond_2
    invoke-virtual {p0, p1}, Lo/G;->addLast(Ljava/lang/Object;)V

    goto :goto_5

    :cond_3
    invoke-virtual {v2, v4}, Lo/x1;->d(Z)V

    const/4 v3, 0x0

    :try_start_0
    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v4

    sget-object v5, Lo/D0;->c:Lo/D0;

    invoke-interface {v4, v5}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v4

    check-cast v4, Lo/O2;

    if-eqz v4, :cond_4

    invoke-interface {v4}, Lo/O2;->a()Z

    move-result v5

    if-nez v5, :cond_4

    check-cast v4, Lo/W2;

    invoke-virtual {v4}, Lo/W2;->m()Ljava/util/concurrent/CancellationException;

    move-result-object p0

    invoke-virtual {p1, v1, p0}, Lo/g1;->a(Ljava/lang/Object;Ljava/util/concurrent/CancellationException;)V

    invoke-static {p0}, Lo/F2;->h(Ljava/lang/Throwable;)Lo/s4;

    move-result-object p0

    invoke-virtual {p1, p0}, Lo/g1;->resumeWith(Ljava/lang/Object;)V

    goto :goto_2

    :catchall_0
    move-exception p0

    goto :goto_4

    :cond_4
    iget-object v1, p1, Lo/g1;->g:Ljava/lang/Object;

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v4

    invoke-static {v4, v1}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v5, Lo/G4;->d:Lo/Q;

    if-eq v1, v5, :cond_5

    invoke-static {v0, v4, v1}, Lo/G4;->o(Lo/B0;Lo/H0;Ljava/lang/Object;)Lo/n5;

    move-result-object v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :cond_5
    move-object v5, v3

    :goto_1
    :try_start_1
    invoke-interface {v0, p0}, Lo/B0;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v5, :cond_6

    :try_start_2
    invoke-virtual {v5}, Lo/n5;->D()Z

    move-result p0

    if-eqz p0, :cond_7

    :cond_6
    invoke-static {v4, v1}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    :cond_7
    :goto_2
    invoke-virtual {v2}, Lo/x1;->e()Z

    move-result p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-nez p0, :cond_7

    :goto_3
    invoke-virtual {v2}, Lo/x1;->b()V

    goto :goto_5

    :catchall_1
    move-exception p0

    if-eqz v5, :cond_8

    :try_start_3
    invoke-virtual {v5}, Lo/n5;->D()Z

    move-result v0

    if-eqz v0, :cond_9

    :cond_8
    invoke-static {v4, v1}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    :cond_9
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_4
    :try_start_4
    invoke-virtual {p1, p0, v3}, Lo/i1;->e(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    goto :goto_3

    :goto_5
    return-void

    :catchall_2
    move-exception p0

    invoke-virtual {v2}, Lo/x1;->b()V

    throw p0

    :cond_a
    invoke-interface {p1, p0}, Lo/B0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public static final l(JJJLjava/lang/String;)J
    .locals 23

    move-wide/from16 v0, p2

    move-wide/from16 v2, p4

    move-object/from16 v4, p6

    const/4 v5, 0x1

    sget v6, Lo/Z4;->a:I

    :try_start_0
    invoke-static {v4}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    const/4 v7, 0x0

    :goto_0
    if-nez v7, :cond_0

    return-wide p0

    :cond_0
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v8

    if-nez v8, :cond_1

    goto/16 :goto_3

    :cond_1
    const/4 v9, 0x0

    invoke-virtual {v7, v9}, Ljava/lang/String;->charAt(I)C

    move-result v10

    const/16 v11, 0x30

    const-wide v12, -0x7fffffffffffffffL    # -4.9E-324

    if-ge v10, v11, :cond_4

    if-ne v8, v5, :cond_2

    goto :goto_3

    :cond_2
    const/16 v11, 0x2b

    if-eq v10, v11, :cond_5

    const/16 v9, 0x2d

    if-eq v10, v9, :cond_3

    goto :goto_3

    :cond_3
    const-wide/high16 v12, -0x8000000000000000L

    move v9, v5

    :cond_4
    move v10, v9

    goto :goto_1

    :cond_5
    move v10, v9

    move v9, v5

    :goto_1
    const-wide/16 v16, 0x0

    move v11, v5

    move-wide/from16 v5, v16

    const-wide v17, -0x38e38e38e38e38eL    # -2.772000429909333E291

    :goto_2
    if-ge v9, v8, :cond_b

    move/from16 p0, v11

    invoke-virtual {v7, v9}, Ljava/lang/String;->charAt(I)C

    move-result v11

    const-wide v19, -0x38e38e38e38e38eL    # -2.772000429909333E291

    const/16 v14, 0xa

    invoke-static {v11, v14}, Ljava/lang/Character;->digit(II)I

    move-result v11

    if-gez v11, :cond_6

    goto :goto_3

    :cond_6
    cmp-long v15, v5, v17

    if-gez v15, :cond_7

    cmp-long v15, v17, v19

    if-nez v15, :cond_9

    move/from16 p1, v8

    move v15, v9

    int-to-long v8, v14

    div-long v17, v12, v8

    cmp-long v8, v5, v17

    if-gez v8, :cond_8

    goto :goto_3

    :cond_7
    move/from16 p1, v8

    move v15, v9

    :cond_8
    int-to-long v8, v14

    mul-long/2addr v5, v8

    int-to-long v8, v11

    add-long v21, v12, v8

    cmp-long v11, v5, v21

    if-gez v11, :cond_a

    :cond_9
    :goto_3
    const/4 v6, 0x0

    goto :goto_5

    :cond_a
    sub-long/2addr v5, v8

    add-int/lit8 v9, v15, 0x1

    move/from16 v11, p0

    move/from16 v8, p1

    goto :goto_2

    :cond_b
    if-eqz v10, :cond_c

    :goto_4
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    goto :goto_5

    :cond_c
    neg-long v5, v5

    goto :goto_4

    :goto_5
    const/16 v5, 0x27

    const-string v8, "System property \'"

    if-eqz v6, :cond_e

    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    move-result-wide v6

    cmp-long v9, v0, v6

    if-gtz v9, :cond_d

    cmp-long v9, v6, v2

    if-gtz v9, :cond_d

    return-wide v6

    :cond_d
    new-instance v9, Ljava/lang/IllegalStateException;

    new-instance v10, Ljava/lang/StringBuilder;

    invoke-direct {v10, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, "\' should be in range "

    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v0, ".."

    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v0, ", but is \'"

    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v9, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v9

    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\' has unrecognized value \'"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static m(Ljava/lang/String;II)I
    .locals 7

    and-int/lit8 p2, p2, 0x8

    if-eqz p2, :cond_0

    const p2, 0x7fffffff

    goto :goto_0

    :cond_0
    const p2, 0x1ffffe

    :goto_0
    int-to-long v0, p1

    const/4 p1, 0x1

    int-to-long v2, p1

    int-to-long v4, p2

    move-object v6, p0

    invoke-static/range {v0 .. v6}, Lo/G4;->l(JJJLjava/lang/String;)J

    move-result-wide p0

    long-to-int p0, p0

    return p0
.end method

.method public static final n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    if-nez p1, :cond_0

    sget-object p1, Lo/m0;->f:Lo/m0;

    invoke-interface {p0, v0, p1}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Lo/F2;->c(Ljava/lang/Object;)V

    :cond_0
    if-ne p1, v0, :cond_1

    sget-object p0, Lo/G4;->d:Lo/Q;

    return-object p0

    :cond_1
    instance-of v0, p1, Ljava/lang/Integer;

    if-eqz v0, :cond_2

    new-instance v0, Lo/h5;

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    invoke-direct {v0, p0, p1}, Lo/h5;-><init>(Lo/H0;I)V

    sget-object p1, Lo/m0;->h:Lo/m0;

    invoke-interface {p0, v0, p1}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :cond_2
    invoke-static {p1}, Lo/l;->r(Ljava/lang/Object;)V

    const/4 p0, 0x0

    throw p0
.end method

.method public static final o(Lo/B0;Lo/H0;Ljava/lang/Object;)Lo/n5;
    .locals 2

    instance-of v0, p0, Lo/R0;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    sget-object v0, Lo/o5;->a:Lo/o5;

    invoke-interface {p1, v0}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v0

    if-eqz v0, :cond_4

    check-cast p0, Lo/R0;

    :cond_1
    instance-of v0, p0, Lo/h1;

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    invoke-interface {p0}, Lo/R0;->getCallerFrame()Lo/R0;

    move-result-object p0

    if-nez p0, :cond_3

    goto :goto_0

    :cond_3
    instance-of v0, p0, Lo/n5;

    if-eqz v0, :cond_1

    move-object v1, p0

    check-cast v1, Lo/n5;

    :goto_0
    if-eqz v1, :cond_4

    invoke-virtual {v1, p1, p2}, Lo/n5;->E(Lo/H0;Ljava/lang/Object;)V

    :cond_4
    :goto_1
    return-object v1
.end method

.method public static final p(Lo/K0;Lo/W1;Lo/B0;)Ljava/lang/Object;
    .locals 4

    invoke-interface {p2}, Lo/B0;->getContext()Lo/H0;

    move-result-object v0

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    sget-object v2, Lo/m0;->e:Lo/m0;

    invoke-interface {p0, v1, v2}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    invoke-interface {v0, p0}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p0

    goto :goto_0

    :cond_0
    invoke-static {v0, p0, v2}, Lo/G4;->e(Lo/H0;Lo/H0;Z)Lo/H0;

    move-result-object p0

    :goto_0
    sget-object v1, Lo/D0;->c:Lo/D0;

    invoke-interface {p0, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v1

    check-cast v1, Lo/O2;

    if-eqz v1, :cond_2

    invoke-interface {v1}, Lo/O2;->a()Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_1

    :cond_1
    check-cast v1, Lo/W2;

    invoke-virtual {v1}, Lo/W2;->m()Ljava/util/concurrent/CancellationException;

    move-result-object p0

    throw p0

    :cond_2
    :goto_1
    if-ne p0, v0, :cond_3

    new-instance v0, Lo/w4;

    invoke-direct {v0, p2, p0}, Lo/w4;-><init>(Lo/B0;Lo/H0;)V

    invoke-static {v0, v0, p1}, Lo/W0;->i(Lo/w4;Lo/w4;Lo/W1;)Ljava/lang/Object;

    move-result-object p0

    goto/16 :goto_3

    :cond_3
    sget-object v1, Lo/D0;->a:Lo/D0;

    invoke-interface {p0, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v3

    invoke-interface {v0, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v0

    invoke-static {v3, v0}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_4

    new-instance v0, Lo/n5;

    invoke-direct {v0, p2, p0}, Lo/n5;-><init>(Lo/B0;Lo/H0;)V

    iget-object p0, v0, Lo/c;->c:Lo/H0;

    invoke-static {p0, v1}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    :try_start_0
    invoke-static {v0, v0, p1}, Lo/W0;->i(Lo/w4;Lo/w4;Lo/W1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {p0, p2}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    move-object p0, p1

    goto :goto_3

    :catchall_0
    move-exception p1

    invoke-static {p0, p2}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    throw p1

    :cond_4
    new-instance v0, Lo/h1;

    invoke-direct {v0, p2, p0}, Lo/w4;-><init>(Lo/B0;Lo/H0;)V

    invoke-static {p1, v0, v0}, Lo/W0;->h(Lo/W1;Lo/c;Lo/c;)V

    :cond_5
    sget-object p0, Lo/h1;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p1

    if-eqz p1, :cond_b

    const/4 p0, 0x2

    if-ne p1, p0, :cond_a

    invoke-virtual {v0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object p0

    instance-of p1, p0, Lo/v2;

    if-eqz p1, :cond_6

    move-object v1, p0

    check-cast v1, Lo/v2;

    :cond_6
    if-eqz v1, :cond_8

    iget-object p1, v1, Lo/v2;->a:Lo/u2;

    if-nez p1, :cond_7

    goto :goto_2

    :cond_7
    move-object p0, p1

    :cond_8
    :goto_2
    nop

    instance-of p1, p0, Lo/q0;

    if-nez p1, :cond_9

    goto :goto_3

    :cond_9
    check-cast p0, Lo/q0;

    iget-object p0, p0, Lo/q0;->a:Ljava/lang/Throwable;

    throw p0

    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Already suspended"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_b
    const/4 p1, 0x1

    invoke-virtual {p0, v0, v2, p1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result p0

    if-eqz p0, :cond_5

    sget-object p0, Lo/Q0;->a:Lo/Q0;

    :goto_3
    return-object p0
.end method

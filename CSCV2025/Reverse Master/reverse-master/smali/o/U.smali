.class public final Lo/U;
.super Lo/i1;
.source "SourceFile"

# interfaces
.implements Lo/T;
.implements Lo/R0;


# static fields
.field public static final synthetic f:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

.field public static final synthetic g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile synthetic _decisionAndIndex$volatile:I

.field private volatile synthetic _parentHandle$volatile:Ljava/lang/Object;

.field private volatile synthetic _state$volatile:Ljava/lang/Object;

.field public final d:Lo/B0;

.field public final e:Lo/H0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-string v0, "_decisionAndIndex$volatile"

    const-class v1, Lo/U;

    invoke-static {v1, v0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/U;->f:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const-string v0, "_state$volatile"

    const-class v2, Ljava/lang/Object;

    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const-string v0, "_parentHandle$volatile"

    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    return-void
.end method

.method public constructor <init>(Lo/B0;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Lo/i1;-><init>(I)V

    iput-object p1, p0, Lo/U;->d:Lo/B0;

    invoke-interface {p1}, Lo/B0;->getContext()Lo/H0;

    move-result-object p1

    iput-object p1, p0, Lo/U;->e:Lo/H0;

    const p1, 0x1fffffff

    iput p1, p0, Lo/U;->_decisionAndIndex$volatile:I

    sget-object p1, Lo/r;->a:Lo/r;

    iput-object p1, p0, Lo/U;->_state$volatile:Ljava/lang/Object;

    return-void
.end method

.method public static o(Lo/S;Ljava/lang/Object;)V
    .locals 3

    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "It\'s prohibited to register multiple handlers, tried to register "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, ", already has "

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/util/concurrent/CancellationException;)V
    .locals 4

    :goto_0
    sget-object p1, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Lo/T3;

    if-nez v1, :cond_9

    instance-of v1, v0, Lo/q0;

    if-eqz v1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v1, v0, Lo/o0;

    const/4 v2, 0x0

    if-eqz v1, :cond_5

    move-object v1, v0

    check-cast v1, Lo/o0;

    iget-object v3, v1, Lo/o0;->e:Ljava/lang/Throwable;

    if-nez v3, :cond_4

    const/16 v3, 0xf

    invoke-static {v1, v2, p2, v3}, Lo/o0;->a(Lo/o0;Lo/S;Ljava/util/concurrent/CancellationException;I)Lo/o0;

    move-result-object v2

    :cond_1
    invoke-virtual {p1, p0, v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    iget-object p1, v1, Lo/o0;->b:Lo/S;

    if-eqz p1, :cond_2

    invoke-virtual {p0, p1, p2}, Lo/U;->g(Lo/S;Ljava/lang/Throwable;)V

    :cond_2
    iget-object p1, v1, Lo/o0;->c:Lo/S1;

    if-eqz p1, :cond_7

    :try_start_0
    invoke-interface {p1, p2}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    new-instance p2, Lo/s0;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Exception in resume onCancellation handler for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p2, v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    iget-object p1, p0, Lo/U;->e:Lo/H0;

    invoke-static {p1, p2}, Lo/F2;->k(Lo/H0;Ljava/lang/Throwable;)V

    goto :goto_1

    :cond_3
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v0, :cond_1

    goto :goto_0

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Must be called at most once"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    new-instance v1, Lo/o0;

    const/16 v3, 0xe

    invoke-direct {v1, v0, v2, p2, v3}, Lo/o0;-><init>(Ljava/lang/Object;Lo/S;Ljava/util/concurrent/CancellationException;I)V

    :cond_6
    invoke-virtual {p1, p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8

    :cond_7
    :goto_1
    return-void

    :cond_8
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eq v2, v0, :cond_6

    goto :goto_0

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Not completed"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final b()Lo/B0;
    .locals 1

    iget-object v0, p0, Lo/U;->d:Lo/B0;

    return-object v0
.end method

.method public final c(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 0

    invoke-super {p0, p1}, Lo/i1;->c(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final d(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    instance-of v0, p1, Lo/o0;

    if-eqz v0, :cond_0

    check-cast p1, Lo/o0;

    iget-object p1, p1, Lo/o0;->a:Ljava/lang/Object;

    :cond_0
    return-object p1
.end method

.method public final f()Ljava/lang/Object;
    .locals 1

    sget-object v0, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final g(Lo/S;Ljava/lang/Throwable;)V
    .locals 2

    :try_start_0
    iget-object p1, p1, Lo/S;->a:Landroidx/activity/contextaware/ContextAwareKt$withContextAvailable$2$1;

    invoke-interface {p1, p2}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    new-instance p2, Lo/s0;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Exception in invokeOnCancellation handler for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p2, v0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    iget-object p1, p0, Lo/U;->e:Lo/H0;

    invoke-static {p1, p2}, Lo/F2;->k(Lo/H0;Ljava/lang/Throwable;)V

    return-void
.end method

.method public final getCallerFrame()Lo/R0;
    .locals 2

    iget-object v0, p0, Lo/U;->d:Lo/B0;

    instance-of v1, v0, Lo/R0;

    if-eqz v1, :cond_0

    check-cast v0, Lo/R0;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final getContext()Lo/H0;
    .locals 1

    iget-object v0, p0, Lo/U;->e:Lo/H0;

    return-object v0
.end method

.method public final h(Ljava/lang/Throwable;)V
    .locals 4

    :goto_0
    sget-object v0, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, Lo/T3;

    if-nez v2, :cond_0

    return-void

    :cond_0
    new-instance v2, Lo/V;

    instance-of v3, v1, Lo/S;

    invoke-direct {v2, p0, p1, v3}, Lo/V;-><init>(Lo/U;Ljava/lang/Throwable;Z)V

    :cond_1
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    move-object v0, v1

    check-cast v0, Lo/T3;

    instance-of v0, v0, Lo/S;

    if-eqz v0, :cond_2

    check-cast v1, Lo/S;

    invoke-virtual {p0, v1, p1}, Lo/U;->g(Lo/S;Ljava/lang/Throwable;)V

    :cond_2
    invoke-virtual {p0}, Lo/U;->n()Z

    move-result p1

    if-nez p1, :cond_4

    sget-object p1, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/k1;

    if-nez v0, :cond_3

    goto :goto_1

    :cond_3
    invoke-interface {v0}, Lo/k1;->dispose()V

    sget-object v0, Lo/S3;->a:Lo/S3;

    invoke-virtual {p1, p0, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_4
    :goto_1
    iget p1, p0, Lo/i1;->c:I

    invoke-virtual {p0, p1}, Lo/U;->i(I)V

    return-void

    :cond_5
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v1, :cond_1

    goto :goto_0
.end method

.method public final i(I)V
    .locals 6

    :cond_0
    sget-object v0, Lo/U;->f:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v1

    shr-int/lit8 v2, v1, 0x1d

    if-eqz v2, :cond_c

    const/4 v0, 0x1

    if-ne v2, v0, :cond_b

    const/4 v1, 0x4

    const/4 v2, 0x0

    if-ne p1, v1, :cond_1

    move v1, v0

    goto :goto_0

    :cond_1
    move v1, v2

    :goto_0
    iget-object v3, p0, Lo/U;->d:Lo/B0;

    if-nez v1, :cond_a

    instance-of v4, v3, Lo/g1;

    if-eqz v4, :cond_a

    const/4 v4, 0x2

    if-eq p1, v0, :cond_3

    if-ne p1, v4, :cond_2

    goto :goto_1

    :cond_2
    move p1, v2

    goto :goto_2

    :cond_3
    :goto_1
    move p1, v0

    :goto_2
    iget v5, p0, Lo/i1;->c:I

    if-eq v5, v0, :cond_4

    if-ne v5, v4, :cond_5

    :cond_4
    move v2, v0

    :cond_5
    if-ne p1, v2, :cond_a

    move-object p1, v3

    check-cast p1, Lo/g1;

    iget-object p1, p1, Lo/g1;->d:Lo/K0;

    move-object v1, v3

    check-cast v1, Lo/g1;

    iget-object v1, v1, Lo/g1;->e:Lo/B0;

    invoke-interface {v1}, Lo/B0;->getContext()Lo/H0;

    move-result-object v1

    invoke-virtual {p1, v1}, Lo/K0;->isDispatchNeeded(Lo/H0;)Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-virtual {p1, v1, p0}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void

    :cond_6
    invoke-static {}, Lo/f5;->a()Lo/x1;

    move-result-object p1

    iget-wide v1, p1, Lo/x1;->a:J

    const-wide v4, 0x100000000L

    cmp-long v1, v1, v4

    if-ltz v1, :cond_8

    iget-object v0, p1, Lo/x1;->c:Lo/G;

    if-nez v0, :cond_7

    new-instance v0, Lo/G;

    invoke-direct {v0}, Lo/G;-><init>()V

    iput-object v0, p1, Lo/x1;->c:Lo/G;

    :cond_7
    invoke-virtual {v0, p0}, Lo/G;->addLast(Ljava/lang/Object;)V

    return-void

    :cond_8
    invoke-virtual {p1, v0}, Lo/x1;->d(Z)V

    :try_start_0
    invoke-static {p0, v3, v0}, Lo/G4;->j(Lo/U;Lo/B0;Z)V

    :cond_9
    invoke-virtual {p1}, Lo/x1;->e()Z

    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v0, :cond_9

    :goto_3
    invoke-virtual {p1}, Lo/x1;->b()V

    goto :goto_4

    :catchall_0
    move-exception v0

    const/4 v1, 0x0

    :try_start_1
    invoke-virtual {p0, v0, v1}, Lo/i1;->e(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_3

    :catchall_1
    move-exception v0

    invoke-virtual {p1}, Lo/x1;->b()V

    throw v0

    :cond_a
    invoke-static {p0, v3, v1}, Lo/G4;->j(Lo/U;Lo/B0;Z)V

    return-void

    :cond_b
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Already resumed"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_c
    const v2, 0x1fffffff

    and-int/2addr v2, v1

    const/high16 v3, 0x40000000    # 2.0f

    add-int/2addr v3, v2

    invoke-virtual {v0, p0, v1, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v0

    if-eqz v0, :cond_0

    :goto_4
    return-void
.end method

.method public final j()Ljava/lang/Object;
    .locals 5

    invoke-virtual {p0}, Lo/U;->n()Z

    move-result v0

    :cond_0
    sget-object v1, Lo/U;->f:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v2

    shr-int/lit8 v3, v2, 0x1d

    if-eqz v3, :cond_7

    const/4 v1, 0x2

    if-ne v3, v1, :cond_6

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Lo/U;->p()V

    :cond_1
    sget-object v0, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v2, v0, Lo/q0;

    if-nez v2, :cond_5

    iget v2, p0, Lo/i1;->c:I

    const/4 v3, 0x1

    if-eq v2, v3, :cond_2

    if-ne v2, v1, :cond_4

    :cond_2
    sget-object v1, Lo/D0;->c:Lo/D0;

    iget-object v2, p0, Lo/U;->e:Lo/H0;

    invoke-interface {v2, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v1

    check-cast v1, Lo/O2;

    if-eqz v1, :cond_4

    invoke-interface {v1}, Lo/O2;->a()Z

    move-result v2

    if-eqz v2, :cond_3

    goto :goto_0

    :cond_3
    check-cast v1, Lo/W2;

    invoke-virtual {v1}, Lo/W2;->m()Ljava/util/concurrent/CancellationException;

    move-result-object v1

    invoke-virtual {p0, v0, v1}, Lo/U;->a(Ljava/lang/Object;Ljava/util/concurrent/CancellationException;)V

    throw v1

    :cond_4
    :goto_0
    invoke-virtual {p0, v0}, Lo/U;->d(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_5
    check-cast v0, Lo/q0;

    iget-object v0, v0, Lo/q0;->a:Ljava/lang/Throwable;

    throw v0

    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Already suspended"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_7
    const v3, 0x1fffffff

    and-int/2addr v3, v2

    const/high16 v4, 0x20000000

    add-int/2addr v4, v3

    invoke-virtual {v1, p0, v2, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v1, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/k1;

    if-nez v1, :cond_8

    invoke-virtual {p0}, Lo/U;->l()Lo/k1;

    :cond_8
    if-eqz v0, :cond_9

    invoke-virtual {p0}, Lo/U;->p()V

    :cond_9
    sget-object v0, Lo/Q0;->a:Lo/Q0;

    return-object v0
.end method

.method public final k()V
    .locals 2

    invoke-virtual {p0}, Lo/U;->l()Lo/k1;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v1, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    instance-of v1, v1, Lo/T3;

    if-nez v1, :cond_1

    invoke-interface {v0}, Lo/k1;->dispose()V

    sget-object v0, Lo/S3;->a:Lo/S3;

    sget-object v1, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final l()Lo/k1;
    .locals 5

    sget-object v0, Lo/D0;->c:Lo/D0;

    iget-object v1, p0, Lo/U;->e:Lo/H0;

    invoke-interface {v1, v0}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v0

    check-cast v0, Lo/O2;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    new-instance v2, Lo/Y;

    invoke-direct {v2, p0}, Lo/Y;-><init>(Lo/U;)V

    const/4 v3, 0x2

    const/4 v4, 0x1

    invoke-static {v0, v4, v2, v3}, Lo/W0;->f(Lo/O2;ZLo/S2;I)Lo/k1;

    move-result-object v0

    :cond_1
    sget-object v2, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v2, p0, v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1

    :goto_0
    return-object v0
.end method

.method public final m(Landroidx/activity/contextaware/ContextAwareKt$withContextAvailable$2$1;)V
    .locals 6

    new-instance v0, Lo/S;

    invoke-direct {v0, p1}, Lo/S;-><init>(Landroidx/activity/contextaware/ContextAwareKt$withContextAvailable$2$1;)V

    :goto_0
    sget-object p1, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, Lo/r;

    if-eqz v2, :cond_2

    :cond_0
    invoke-virtual {p1, p0, v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    goto/16 :goto_2

    :cond_1
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eq v2, v1, :cond_0

    goto :goto_0

    :cond_2
    instance-of v2, v1, Lo/S;

    const/4 v3, 0x0

    if-nez v2, :cond_f

    instance-of v2, v1, Lo/q0;

    if-eqz v2, :cond_6

    move-object p1, v1

    check-cast p1, Lo/q0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v2, 0x1

    sget-object v4, Lo/q0;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const/4 v5, 0x0

    invoke-virtual {v4, p1, v5, v2}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v2

    if-eqz v2, :cond_5

    instance-of v2, v1, Lo/V;

    if-eqz v2, :cond_d

    if-eqz v1, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v3

    :goto_1
    if-eqz p1, :cond_4

    iget-object v3, p1, Lo/q0;->a:Ljava/lang/Throwable;

    :cond_4
    invoke-virtual {p0, v0, v3}, Lo/U;->g(Lo/S;Ljava/lang/Throwable;)V

    return-void

    :cond_5
    invoke-static {v0, v1}, Lo/U;->o(Lo/S;Ljava/lang/Object;)V

    throw v3

    :cond_6
    instance-of v2, v1, Lo/o0;

    if-eqz v2, :cond_b

    move-object v2, v1

    check-cast v2, Lo/o0;

    iget-object v4, v2, Lo/o0;->b:Lo/S;

    if-nez v4, :cond_a

    iget-object v4, v2, Lo/o0;->e:Ljava/lang/Throwable;

    if-eqz v4, :cond_7

    invoke-virtual {p0, v0, v4}, Lo/U;->g(Lo/S;Ljava/lang/Throwable;)V

    return-void

    :cond_7
    const/16 v4, 0x1d

    invoke-static {v2, v0, v3, v4}, Lo/o0;->a(Lo/o0;Lo/S;Ljava/util/concurrent/CancellationException;I)Lo/o0;

    move-result-object v2

    :cond_8
    invoke-virtual {p1, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_9

    goto :goto_2

    :cond_9
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v1, :cond_8

    goto :goto_0

    :cond_a
    invoke-static {v0, v1}, Lo/U;->o(Lo/S;Ljava/lang/Object;)V

    throw v3

    :cond_b
    new-instance v2, Lo/o0;

    const/16 v4, 0x1c

    invoke-direct {v2, v1, v0, v3, v4}, Lo/o0;-><init>(Ljava/lang/Object;Lo/S;Ljava/util/concurrent/CancellationException;I)V

    :cond_c
    invoke-virtual {p1, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_e

    :cond_d
    :goto_2
    return-void

    :cond_e
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v1, :cond_c

    goto/16 :goto_0

    :cond_f
    invoke-static {v0, v1}, Lo/U;->o(Lo/S;Ljava/lang/Object;)V

    throw v3
.end method

.method public final n()Z
    .locals 2

    iget v0, p0, Lo/i1;->c:I

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    const-string v0, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<*>"

    iget-object v1, p0, Lo/U;->d:Lo/B0;

    invoke-static {v1, v0}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Lo/g1;

    sget-object v0, Lo/g1;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final p()V
    .locals 5

    iget-object v0, p0, Lo/U;->d:Lo/B0;

    instance-of v1, v0, Lo/g1;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast v0, Lo/g1;

    goto :goto_0

    :cond_0
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_9

    :goto_1
    sget-object v1, Lo/g1;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Lo/G4;->b:Lo/Q;

    if-ne v3, v4, :cond_3

    :cond_1
    invoke-virtual {v1, v0, v4, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_3

    :cond_2
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v4, :cond_1

    goto :goto_1

    :cond_3
    instance-of v4, v3, Ljava/lang/Throwable;

    if-eqz v4, :cond_8

    :goto_2
    invoke-virtual {v1, v0, v3, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6

    move-object v2, v3

    check-cast v2, Ljava/lang/Throwable;

    :goto_3
    if-nez v2, :cond_4

    goto :goto_5

    :cond_4
    sget-object v0, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/k1;

    if-nez v1, :cond_5

    goto :goto_4

    :cond_5
    invoke-interface {v1}, Lo/k1;->dispose()V

    sget-object v1, Lo/S3;->a:Lo/S3;

    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :goto_4
    invoke-virtual {p0, v2}, Lo/U;->h(Ljava/lang/Throwable;)V

    return-void

    :cond_6
    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v3, :cond_7

    goto :goto_2

    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Failed requirement."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Inconsistent state "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_9
    :goto_5
    return-void
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 8

    invoke-static {p1}, Lo/t4;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Lo/q0;

    invoke-direct {p1, v1, v0}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    :goto_0
    iget v0, p0, Lo/i1;->c:I

    :goto_1
    sget-object v2, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    instance-of v4, v3, Lo/T3;

    const/4 v5, 0x1

    if-eqz v4, :cond_a

    move-object v4, v3

    check-cast v4, Lo/T3;

    instance-of v6, p1, Lo/q0;

    if-eqz v6, :cond_2

    :cond_1
    :goto_2
    move-object v4, p1

    goto :goto_4

    :cond_2
    if-eq v0, v5, :cond_3

    const/4 v5, 0x2

    if-ne v0, v5, :cond_1

    :cond_3
    instance-of v5, v4, Lo/S;

    if-nez v5, :cond_4

    goto :goto_2

    :cond_4
    new-instance v5, Lo/o0;

    const/4 v6, 0x0

    if-eqz v4, :cond_5

    check-cast v4, Lo/S;

    goto :goto_3

    :cond_5
    move-object v4, v6

    :goto_3
    const/16 v7, 0x10

    invoke-direct {v5, p1, v4, v6, v7}, Lo/o0;-><init>(Ljava/lang/Object;Lo/S;Ljava/util/concurrent/CancellationException;I)V

    move-object v4, v5

    :cond_6
    :goto_4
    invoke-virtual {v2, p0, v3, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_9

    invoke-virtual {p0}, Lo/U;->n()Z

    move-result p1

    if-nez p1, :cond_8

    sget-object p1, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/k1;

    if-nez v1, :cond_7

    goto :goto_5

    :cond_7
    invoke-interface {v1}, Lo/k1;->dispose()V

    sget-object v1, Lo/S3;->a:Lo/S3;

    invoke-virtual {p1, p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_8
    :goto_5
    invoke-virtual {p0, v0}, Lo/U;->i(I)V

    return-void

    :cond_9
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-eq v5, v3, :cond_6

    goto :goto_1

    :cond_a
    instance-of v0, v3, Lo/V;

    if-eqz v0, :cond_b

    check-cast v3, Lo/V;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Lo/V;->c:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v0, v3, v1, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v0

    if-eqz v0, :cond_b

    return-void

    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Already resumed, but proposed with update "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "CancellableContinuation("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lo/U;->d:Lo/B0;

    invoke-static {v1}, Lo/W0;->j(Lo/B0;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "){"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget-object v1, Lo/U;->g:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, Lo/T3;

    if-eqz v2, :cond_0

    const-string v1, "Active"

    goto :goto_0

    :cond_0
    instance-of v1, v1, Lo/V;

    if-eqz v1, :cond_1

    const-string v1, "Cancelled"

    goto :goto_0

    :cond_1
    const-string v1, "Completed"

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "}@"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p0}, Lo/W0;->d(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

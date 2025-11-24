.class public Lo/W2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/O2;
.implements Lo/X3;


# static fields
.field public static final synthetic a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile synthetic _parentHandle$volatile:Ljava/lang/Object;

.field private volatile synthetic _state$volatile:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-string v0, "_state$volatile"

    const-class v1, Lo/W2;

    const-class v2, Ljava/lang/Object;

    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const-string v0, "_parentHandle$volatile"

    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/W2;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    sget-object p1, Lo/F2;->h:Lo/o1;

    goto :goto_0

    :cond_0
    sget-object p1, Lo/F2;->g:Lo/o1;

    :goto_0
    iput-object p1, p0, Lo/W2;->_state$volatile:Ljava/lang/Object;

    return-void
.end method

.method public static B(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    instance-of v0, p0, Lo/U2;

    if-eqz v0, :cond_1

    check-cast p0, Lo/U2;

    invoke-virtual {p0}, Lo/U2;->e()Z

    move-result v0

    if-eqz v0, :cond_0

    const-string p0, "Cancelling"

    return-object p0

    :cond_0
    invoke-virtual {p0}, Lo/U2;->f()Z

    move-result p0

    if-eqz p0, :cond_2

    const-string p0, "Completing"

    return-object p0

    :cond_1
    instance-of v0, p0, Lo/u2;

    if-eqz v0, :cond_4

    check-cast p0, Lo/u2;

    invoke-interface {p0}, Lo/u2;->a()Z

    move-result p0

    if-eqz p0, :cond_3

    :cond_2
    const-string p0, "Active"

    return-object p0

    :cond_3
    const-string p0, "New"

    return-object p0

    :cond_4
    instance-of p0, p0, Lo/q0;

    if-eqz p0, :cond_5

    const-string p0, "Cancelled"

    return-object p0

    :cond_5
    const-string p0, "Completed"

    return-object p0
.end method

.method public static w(Lo/t3;)Lo/a0;
    .locals 2

    :goto_0
    invoke-virtual {p0}, Lo/t3;->i()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Lo/t3;->e()Lo/t3;

    move-result-object v0

    if-nez v0, :cond_1

    sget-object v1, Lo/t3;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lo/t3;

    :goto_1
    invoke-virtual {p0}, Lo/t3;->i()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lo/t3;

    goto :goto_1

    :cond_1
    move-object p0, v0

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Lo/t3;->h()Lo/t3;

    move-result-object p0

    invoke-virtual {p0}, Lo/t3;->i()Z

    move-result v0

    if-nez v0, :cond_2

    instance-of v0, p0, Lo/a0;

    if-eqz v0, :cond_3

    check-cast p0, Lo/a0;

    return-object p0

    :cond_3
    instance-of v0, p0, Lo/R3;

    if-eqz v0, :cond_2

    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public final A(Lo/S2;)V
    .locals 3

    new-instance v0, Lo/R3;

    invoke-direct {v0}, Lo/t3;-><init>()V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Lo/t3;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Lo/t3;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :goto_0
    invoke-virtual {p1}, Lo/t3;->g()Ljava/lang/Object;

    move-result-object v2

    if-eq v2, p1, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v1, p1, p1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-virtual {v0, p1}, Lo/t3;->f(Lo/t3;)V

    :goto_1
    invoke-virtual {p1}, Lo/t3;->h()Lo/t3;

    move-result-object v2

    :cond_1
    sget-object v0, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0, p1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    return-void

    :cond_2
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eq v0, p1, :cond_1

    return-void

    :cond_3
    invoke-virtual {v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eq v2, p1, :cond_0

    goto :goto_0
.end method

.method public final C(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    instance-of v0, p1, Lo/u2;

    if-nez v0, :cond_0

    sget-object p1, Lo/F2;->b:Lo/Q;

    return-object p1

    :cond_0
    instance-of v0, p1, Lo/o1;

    if-nez v0, :cond_1

    instance-of v0, p1, Lo/S2;

    if-eqz v0, :cond_5

    :cond_1
    instance-of v0, p1, Lo/a0;

    if-nez v0, :cond_5

    instance-of v0, p2, Lo/q0;

    if-nez v0, :cond_5

    move-object v0, p1

    check-cast v0, Lo/u2;

    instance-of p1, p2, Lo/u2;

    if-eqz p1, :cond_2

    new-instance p1, Lo/v2;

    move-object v1, p2

    check-cast v1, Lo/u2;

    invoke-direct {p1, v1}, Lo/v2;-><init>(Lo/u2;)V

    move-object v1, p1

    goto :goto_0

    :cond_2
    move-object v1, p2

    :cond_3
    :goto_0
    sget-object p1, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-virtual {p0, p2}, Lo/W2;->y(Ljava/lang/Object;)V

    invoke-virtual {p0, v0, p2}, Lo/W2;->j(Lo/u2;Ljava/lang/Object;)V

    return-object p2

    :cond_4
    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eq p1, v0, :cond_3

    sget-object p1, Lo/F2;->d:Lo/Q;

    return-object p1

    :cond_5
    check-cast p1, Lo/u2;

    invoke-virtual {p0, p1}, Lo/W2;->o(Lo/u2;)Lo/R3;

    move-result-object v0

    if-nez v0, :cond_6

    sget-object p1, Lo/F2;->d:Lo/Q;

    return-object p1

    :cond_6
    instance-of v1, p1, Lo/U2;

    const/4 v2, 0x0

    if-eqz v1, :cond_7

    move-object v1, p1

    check-cast v1, Lo/U2;

    goto :goto_1

    :cond_7
    move-object v1, v2

    :goto_1
    if-nez v1, :cond_8

    new-instance v1, Lo/U2;

    invoke-direct {v1, v0, v2}, Lo/U2;-><init>(Lo/R3;Ljava/lang/Throwable;)V

    :cond_8
    monitor-enter v1

    :try_start_0
    invoke-virtual {v1}, Lo/U2;->f()Z

    move-result v3

    if-eqz v3, :cond_9

    sget-object p1, Lo/F2;->b:Lo/Q;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    return-object p1

    :cond_9
    :try_start_1
    sget-object v3, Lo/U2;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const/4 v4, 0x1

    invoke-virtual {v3, v1, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->set(Ljava/lang/Object;I)V

    if-eq v1, p1, :cond_c

    sget-object v3, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_a
    invoke-virtual {v3, p0, p1, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_b

    goto :goto_2

    :cond_b
    invoke-virtual {v3, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-eq v5, p1, :cond_a

    sget-object p1, Lo/F2;->d:Lo/Q;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v1

    return-object p1

    :cond_c
    :goto_2
    :try_start_2
    invoke-virtual {v1}, Lo/U2;->e()Z

    move-result v3

    instance-of v5, p2, Lo/q0;

    if-eqz v5, :cond_d

    move-object v5, p2

    check-cast v5, Lo/q0;

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_7

    :cond_d
    move-object v5, v2

    :goto_3
    if-eqz v5, :cond_e

    iget-object v5, v5, Lo/q0;->a:Ljava/lang/Throwable;

    invoke-virtual {v1, v5}, Lo/U2;->b(Ljava/lang/Throwable;)V

    :cond_e
    invoke-virtual {v1}, Lo/U2;->c()Ljava/lang/Throwable;

    move-result-object v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-nez v3, :cond_f

    goto :goto_4

    :cond_f
    move-object v5, v2

    :goto_4
    monitor-exit v1

    if-eqz v5, :cond_10

    invoke-virtual {p0, v0, v5}, Lo/W2;->x(Lo/R3;Ljava/lang/Throwable;)V

    :cond_10
    instance-of v0, p1, Lo/a0;

    if-eqz v0, :cond_11

    move-object v0, p1

    check-cast v0, Lo/a0;

    goto :goto_5

    :cond_11
    move-object v0, v2

    :goto_5
    if-nez v0, :cond_12

    invoke-interface {p1}, Lo/u2;->d()Lo/R3;

    move-result-object p1

    if-eqz p1, :cond_13

    invoke-static {p1}, Lo/W2;->w(Lo/t3;)Lo/a0;

    move-result-object v2

    goto :goto_6

    :cond_12
    move-object v2, v0

    :cond_13
    :goto_6
    if-eqz v2, :cond_16

    :cond_14
    iget-object p1, v2, Lo/a0;->e:Lo/W2;

    new-instance v0, Lo/T2;

    invoke-direct {v0, p0, v1, v2, p2}, Lo/T2;-><init>(Lo/W2;Lo/U2;Lo/a0;Ljava/lang/Object;)V

    const/4 v3, 0x0

    invoke-static {p1, v3, v0, v4}, Lo/W0;->f(Lo/O2;ZLo/S2;I)Lo/k1;

    move-result-object p1

    sget-object v0, Lo/S3;->a:Lo/S3;

    if-eq p1, v0, :cond_15

    sget-object p1, Lo/F2;->c:Lo/Q;

    return-object p1

    :cond_15
    invoke-static {v2}, Lo/W2;->w(Lo/t3;)Lo/a0;

    move-result-object v2

    if-nez v2, :cond_14

    :cond_16
    invoke-virtual {p0, v1, p2}, Lo/W2;->l(Lo/U2;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :goto_7
    monitor-exit v1

    throw p1
.end method

.method public a()Z
    .locals 2

    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Lo/u2;

    if-eqz v1, :cond_0

    check-cast v0, Lo/u2;

    invoke-interface {v0}, Lo/u2;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final c(Lo/u2;Lo/R3;Lo/S2;)Z
    .locals 6

    new-instance v0, Lo/V2;

    invoke-direct {v0, p3, p0, p1}, Lo/V2;-><init>(Lo/S2;Lo/W2;Lo/u2;)V

    :goto_0
    invoke-virtual {p2}, Lo/t3;->e()Lo/t3;

    move-result-object p1

    if-nez p1, :cond_1

    sget-object v1, Lo/t3;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lo/t3;

    :goto_1
    invoke-virtual {p1}, Lo/t3;->i()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_2

    :cond_0
    invoke-virtual {v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lo/t3;

    goto :goto_1

    :cond_1
    :goto_2
    sget-object v1, Lo/t3;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p3, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Lo/t3;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p3, p2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object p2, v0, Lo/V2;->c:Lo/R3;

    :cond_2
    invoke-virtual {v1, p1, p2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x0

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v2, :cond_4

    invoke-virtual {v0, p1}, Lo/I;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_3

    move p1, v5

    goto :goto_3

    :cond_3
    move p1, v4

    goto :goto_3

    :cond_4
    invoke-virtual {v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eq v2, p2, :cond_2

    move p1, v3

    :goto_3
    if-eq p1, v5, :cond_6

    if-eq p1, v4, :cond_5

    goto :goto_0

    :cond_5
    return v3

    :cond_6
    return v5
.end method

.method public d(Ljava/lang/Object;)V
    .locals 0

    return-void
.end method

.method public e(Ljava/lang/Object;)V
    .locals 0

    invoke-virtual {p0, p1}, Lo/W2;->d(Ljava/lang/Object;)V

    return-void
.end method

.method public final f(Ljava/lang/Object;)Z
    .locals 9

    sget-object v0, Lo/F2;->b:Lo/Q;

    instance-of v1, p0, Lo/W4;

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eqz v1, :cond_3

    :cond_0
    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Lo/u2;

    if-eqz v1, :cond_2

    instance-of v1, v0, Lo/U2;

    if-eqz v1, :cond_1

    move-object v1, v0

    check-cast v1, Lo/U2;

    invoke-virtual {v1}, Lo/U2;->f()Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_1
    new-instance v1, Lo/q0;

    invoke-virtual {p0, p1}, Lo/W2;->k(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v4

    invoke-direct {v1, v3, v4}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    invoke-virtual {p0, v0, v1}, Lo/W2;->C(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Lo/F2;->d:Lo/Q;

    if-eq v0, v1, :cond_0

    goto :goto_1

    :cond_2
    :goto_0
    sget-object v0, Lo/F2;->b:Lo/Q;

    :goto_1
    sget-object v1, Lo/F2;->c:Lo/Q;

    if-ne v0, v1, :cond_3

    goto/16 :goto_8

    :cond_3
    sget-object v1, Lo/F2;->b:Lo/Q;

    if-ne v0, v1, :cond_12

    const/4 v0, 0x0

    move-object v1, v0

    :cond_4
    :goto_2
    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v4

    instance-of v5, v4, Lo/U2;

    if-eqz v5, :cond_a

    monitor-enter v4

    :try_start_0
    move-object v5, v4

    check-cast v5, Lo/U2;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Lo/U2;->d:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v6, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    sget-object v6, Lo/F2;->f:Lo/Q;

    if-ne v5, v6, :cond_5

    move v5, v2

    goto :goto_3

    :cond_5
    move v5, v3

    :goto_3
    if-eqz v5, :cond_6

    sget-object p1, Lo/F2;->e:Lo/Q;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v4

    :goto_4
    move-object v0, p1

    goto/16 :goto_7

    :cond_6
    :try_start_1
    move-object v5, v4

    check-cast v5, Lo/U2;

    invoke-virtual {v5}, Lo/U2;->e()Z

    move-result v5

    if-nez v1, :cond_7

    invoke-virtual {p0, p1}, Lo/W2;->k(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    goto :goto_5

    :catchall_0
    move-exception p1

    goto :goto_6

    :cond_7
    :goto_5
    move-object p1, v4

    check-cast p1, Lo/U2;

    invoke-virtual {p1, v1}, Lo/U2;->b(Ljava/lang/Throwable;)V

    move-object p1, v4

    check-cast p1, Lo/U2;

    invoke-virtual {p1}, Lo/U2;->c()Ljava/lang/Throwable;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-nez v5, :cond_8

    move-object v0, p1

    :cond_8
    monitor-exit v4

    if-eqz v0, :cond_9

    check-cast v4, Lo/U2;

    iget-object p1, v4, Lo/U2;->a:Lo/R3;

    invoke-virtual {p0, p1, v0}, Lo/W2;->x(Lo/R3;Ljava/lang/Throwable;)V

    :cond_9
    sget-object p1, Lo/F2;->b:Lo/Q;

    goto :goto_4

    :goto_6
    monitor-exit v4

    throw p1

    :cond_a
    instance-of v5, v4, Lo/u2;

    if-eqz v5, :cond_11

    if-nez v1, :cond_b

    invoke-virtual {p0, p1}, Lo/W2;->k(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    :cond_b
    move-object v5, v4

    check-cast v5, Lo/u2;

    invoke-interface {v5}, Lo/u2;->a()Z

    move-result v6

    if-eqz v6, :cond_f

    invoke-virtual {p0, v5}, Lo/W2;->o(Lo/u2;)Lo/R3;

    move-result-object v6

    if-nez v6, :cond_c

    goto :goto_2

    :cond_c
    new-instance v7, Lo/U2;

    invoke-direct {v7, v6, v1}, Lo/U2;-><init>(Lo/R3;Ljava/lang/Throwable;)V

    :cond_d
    sget-object v4, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v4, p0, v5, v7}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_e

    invoke-virtual {p0, v6, v1}, Lo/W2;->x(Lo/R3;Ljava/lang/Throwable;)V

    sget-object p1, Lo/F2;->b:Lo/Q;

    goto :goto_4

    :cond_e
    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-eq v4, v5, :cond_d

    goto/16 :goto_2

    :cond_f
    new-instance v5, Lo/q0;

    invoke-direct {v5, v3, v1}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    invoke-virtual {p0, v4, v5}, Lo/W2;->C(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    sget-object v6, Lo/F2;->b:Lo/Q;

    if-eq v5, v6, :cond_10

    sget-object v4, Lo/F2;->d:Lo/Q;

    if-eq v5, v4, :cond_4

    move-object v0, v5

    goto :goto_7

    :cond_10
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot happen in "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_11
    sget-object p1, Lo/F2;->e:Lo/Q;

    goto/16 :goto_4

    :cond_12
    :goto_7
    sget-object p1, Lo/F2;->b:Lo/Q;

    if-ne v0, p1, :cond_13

    goto :goto_8

    :cond_13
    sget-object p1, Lo/F2;->c:Lo/Q;

    if-ne v0, p1, :cond_14

    :goto_8
    return v2

    :cond_14
    sget-object p1, Lo/F2;->e:Lo/Q;

    if-ne v0, p1, :cond_15

    return v3

    :cond_15
    invoke-virtual {p0, v0}, Lo/W2;->d(Ljava/lang/Object;)V

    return v2
.end method

.method public final fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Lo/W1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final g(Ljava/lang/Throwable;)Z
    .locals 3

    invoke-virtual {p0}, Lo/W2;->u()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Ljava/util/concurrent/CancellationException;

    sget-object v1, Lo/W2;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/Z;

    if-eqz v1, :cond_4

    sget-object v2, Lo/S3;->a:Lo/S3;

    if-ne v1, v2, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v1, p1}, Lo/Z;->b(Ljava/lang/Throwable;)Z

    move-result p1

    if-nez p1, :cond_3

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    return p1

    :cond_3
    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_4
    :goto_1
    return v0
.end method

.method public final get(Lo/G0;)Lo/F0;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Lo/D0;->c:Lo/D0;

    invoke-static {v0, p1}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    return-object p0

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final getKey()Lo/G0;
    .locals 1

    sget-object v0, Lo/D0;->c:Lo/D0;

    return-object v0
.end method

.method public h()Ljava/lang/String;
    .locals 1

    const-string v0, "Job was cancelled"

    return-object v0
.end method

.method public i(Ljava/lang/Throwable;)Z
    .locals 1

    instance-of v0, p1, Ljava/util/concurrent/CancellationException;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0, p1}, Lo/W2;->f(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Lo/W2;->n()Z

    move-result p1

    if-eqz p1, :cond_1

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final j(Lo/u2;Ljava/lang/Object;)V
    .locals 7

    sget-object v0, Lo/W2;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/Z;

    if-eqz v1, :cond_0

    invoke-interface {v1}, Lo/k1;->dispose()V

    sget-object v1, Lo/S3;->a:Lo/S3;

    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_0
    instance-of v0, p2, Lo/q0;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    check-cast p2, Lo/q0;

    goto :goto_0

    :cond_1
    move-object p2, v1

    :goto_0
    if-eqz p2, :cond_2

    iget-object p2, p2, Lo/q0;->a:Ljava/lang/Throwable;

    goto :goto_1

    :cond_2
    move-object p2, v1

    :goto_1
    instance-of v0, p1, Lo/S2;

    const-string v2, " for "

    const-string v3, "Exception in completion handler "

    if-eqz v0, :cond_3

    :try_start_0
    move-object v0, p1

    check-cast v0, Lo/S2;

    invoke-interface {v0, p2}, Lo/E2;->c(Ljava/lang/Throwable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p2

    new-instance v0, Lo/s0;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-virtual {p0, v0}, Lo/W2;->r(Lo/s0;)V

    goto :goto_4

    :cond_3
    invoke-interface {p1}, Lo/u2;->d()Lo/R3;

    move-result-object p1

    if-eqz p1, :cond_7

    invoke-virtual {p1}, Lo/t3;->g()Ljava/lang/Object;

    move-result-object v0

    const-string v4, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode{ kotlinx.coroutines.internal.LockFreeLinkedListKt.Node }"

    invoke-static {v0, v4}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Lo/t3;

    :goto_2
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_6

    instance-of v4, v0, Lo/S2;

    if-eqz v4, :cond_5

    move-object v4, v0

    check-cast v4, Lo/S2;

    :try_start_1
    invoke-interface {v4, p2}, Lo/E2;->c(Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_3

    :catchall_1
    move-exception v5

    if-eqz v1, :cond_4

    invoke-static {v1, v5}, Lo/W0;->c(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    goto :goto_3

    :cond_4
    new-instance v1, Lo/s0;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v1, v4, v5}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_5
    :goto_3
    invoke-virtual {v0}, Lo/t3;->h()Lo/t3;

    move-result-object v0

    goto :goto_2

    :cond_6
    if-eqz v1, :cond_7

    invoke-virtual {p0, v1}, Lo/W2;->r(Lo/s0;)V

    :cond_7
    :goto_4
    return-void
.end method

.method public final k(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 4

    instance-of v0, p1, Ljava/lang/Throwable;

    if-eqz v0, :cond_0

    check-cast p1, Ljava/lang/Throwable;

    return-object p1

    :cond_0
    check-cast p1, Lo/X3;

    check-cast p1, Lo/W2;

    invoke-virtual {p1}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Lo/U2;

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    move-object v1, v0

    check-cast v1, Lo/U2;

    invoke-virtual {v1}, Lo/U2;->c()Ljava/lang/Throwable;

    move-result-object v1

    goto :goto_0

    :cond_1
    instance-of v1, v0, Lo/q0;

    if-eqz v1, :cond_2

    move-object v1, v0

    check-cast v1, Lo/q0;

    iget-object v1, v1, Lo/q0;->a:Ljava/lang/Throwable;

    goto :goto_0

    :cond_2
    instance-of v1, v0, Lo/u2;

    if-nez v1, :cond_5

    move-object v1, v2

    :goto_0
    instance-of v3, v1, Ljava/util/concurrent/CancellationException;

    if-eqz v3, :cond_3

    move-object v2, v1

    check-cast v2, Ljava/util/concurrent/CancellationException;

    :cond_3
    if-nez v2, :cond_4

    new-instance v2, Lo/P2;

    invoke-static {v0}, Lo/W2;->B(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const-string v3, "Parent job is "

    invoke-virtual {v3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v2, v0, v1, p1}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    :cond_4
    return-object v2

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot be cancelling child in this state: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final l(Lo/U2;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    instance-of v0, p2, Lo/q0;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Lo/q0;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    iget-object v0, v0, Lo/q0;->a:Ljava/lang/Throwable;

    goto :goto_1

    :cond_1
    move-object v0, v1

    :goto_1
    monitor-enter p1

    :try_start_0
    invoke-virtual {p1}, Lo/U2;->e()Z

    invoke-virtual {p1, v0}, Lo/U2;->g(Ljava/lang/Throwable;)Ljava/util/ArrayList;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    move-result v3

    const/4 v4, 0x0

    if-eqz v3, :cond_2

    invoke-virtual {p1}, Lo/U2;->e()Z

    move-result v3

    if-eqz v3, :cond_6

    new-instance v3, Lo/P2;

    invoke-virtual {p0}, Lo/W2;->h()Ljava/lang/String;

    move-result-object v5

    invoke-direct {v3, v5, v1, p0}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    move-object v1, v3

    goto :goto_2

    :cond_2
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_4

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Ljava/lang/Throwable;

    instance-of v6, v6, Ljava/util/concurrent/CancellationException;

    if-nez v6, :cond_3

    move-object v1, v5

    :cond_4
    check-cast v1, Ljava/lang/Throwable;

    if-eqz v1, :cond_5

    goto :goto_2

    :cond_5
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Throwable;

    :cond_6
    :goto_2
    const/4 v3, 0x1

    if-eqz v1, :cond_9

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v5

    if-gt v5, v3, :cond_7

    goto :goto_4

    :cond_7
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v5

    new-instance v6, Ljava/util/IdentityHashMap;

    invoke-direct {v6, v5}, Ljava/util/IdentityHashMap;-><init>(I)V

    invoke-static {v6}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    move-result-object v5

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_8
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_9

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Throwable;

    if-eq v6, v1, :cond_8

    if-eq v6, v1, :cond_8

    instance-of v7, v6, Ljava/util/concurrent/CancellationException;

    if-nez v7, :cond_8

    invoke-interface {v5, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    invoke-static {v1, v6}, Lo/W0;->c(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    :cond_9
    :goto_4
    monitor-exit p1

    if-nez v1, :cond_a

    goto :goto_5

    :cond_a
    if-ne v1, v0, :cond_b

    goto :goto_5

    :cond_b
    new-instance p2, Lo/q0;

    invoke-direct {p2, v4, v1}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    :goto_5
    if-eqz v1, :cond_d

    invoke-virtual {p0, v1}, Lo/W2;->g(Ljava/lang/Throwable;)Z

    move-result v0

    if-nez v0, :cond_c

    invoke-virtual {p0, v1}, Lo/W2;->q(Ljava/lang/Throwable;)Z

    move-result v0

    if-eqz v0, :cond_d

    :cond_c
    const-string v0, "null cannot be cast to non-null type kotlinx.coroutines.CompletedExceptionally"

    invoke-static {p2, v0}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p2

    check-cast v0, Lo/q0;

    sget-object v1, Lo/q0;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, v0, v4, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    :cond_d
    invoke-virtual {p0, p2}, Lo/W2;->y(Ljava/lang/Object;)V

    sget-object v0, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    instance-of v1, p2, Lo/u2;

    if-eqz v1, :cond_e

    new-instance v1, Lo/v2;

    move-object v2, p2

    check-cast v2, Lo/u2;

    invoke-direct {v1, v2}, Lo/v2;-><init>(Lo/u2;)V

    goto :goto_6

    :cond_e
    move-object v1, p2

    :cond_f
    :goto_6
    invoke-virtual {v0, p0, p1, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_10

    goto :goto_7

    :cond_10
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eq v2, p1, :cond_f

    :goto_7
    invoke-virtual {p0, p1, p2}, Lo/W2;->j(Lo/u2;Ljava/lang/Object;)V

    return-object p2

    :catchall_0
    move-exception p2

    monitor-exit p1

    throw p2
.end method

.method public final m()Ljava/util/concurrent/CancellationException;
    .locals 4

    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Lo/U2;

    const/4 v2, 0x0

    const-string v3, "Job is still new or active: "

    if-eqz v1, :cond_4

    check-cast v0, Lo/U2;

    invoke-virtual {v0}, Lo/U2;->c()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_3

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    const-string v3, " is cancelling"

    invoke-virtual {v1, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    instance-of v3, v0, Ljava/util/concurrent/CancellationException;

    if-eqz v3, :cond_0

    move-object v2, v0

    check-cast v2, Ljava/util/concurrent/CancellationException;

    :cond_0
    if-nez v2, :cond_2

    new-instance v2, Lo/P2;

    if-nez v1, :cond_1

    invoke-virtual {p0}, Lo/W2;->h()Ljava/lang/String;

    move-result-object v1

    :cond_1
    invoke-direct {v2, v1, v0, p0}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    :cond_2
    return-object v2

    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_4
    instance-of v1, v0, Lo/u2;

    if-nez v1, :cond_8

    instance-of v1, v0, Lo/q0;

    if-eqz v1, :cond_7

    check-cast v0, Lo/q0;

    iget-object v0, v0, Lo/q0;->a:Ljava/lang/Throwable;

    instance-of v1, v0, Ljava/util/concurrent/CancellationException;

    if-eqz v1, :cond_5

    move-object v2, v0

    check-cast v2, Ljava/util/concurrent/CancellationException;

    :cond_5
    if-nez v2, :cond_6

    new-instance v1, Lo/P2;

    invoke-virtual {p0}, Lo/W2;->h()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2, v0, p0}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    return-object v1

    :cond_6
    return-object v2

    :cond_7
    new-instance v0, Lo/P2;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    const-string v3, " has completed normally"

    invoke-virtual {v1, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1, v2, p0}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    return-object v0

    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final minusKey(Lo/G0;)Lo/H0;
    .locals 0

    invoke-static {p0, p1}, Lo/F2;->n(Lo/F0;Lo/G0;)Lo/H0;

    move-result-object p1

    return-object p1
.end method

.method public n()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final o(Lo/u2;)Lo/R3;
    .locals 3

    invoke-interface {p1}, Lo/u2;->d()Lo/R3;

    move-result-object v0

    if-nez v0, :cond_2

    instance-of v0, p1, Lo/o1;

    if-eqz v0, :cond_0

    new-instance p1, Lo/R3;

    invoke-direct {p1}, Lo/t3;-><init>()V

    return-object p1

    :cond_0
    instance-of v0, p1, Lo/S2;

    if-eqz v0, :cond_1

    check-cast p1, Lo/S2;

    invoke-virtual {p0, p1}, Lo/W2;->A(Lo/S2;)V

    const/4 p1, 0x0

    return-object p1

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "State should have list: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    return-object v0
.end method

.method public final p()Ljava/lang/Object;
    .locals 2

    :goto_0
    sget-object v0, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Lo/U3;

    if-nez v1, :cond_0

    return-object v0

    :cond_0
    check-cast v0, Lo/U3;

    invoke-virtual {v0, p0}, Lo/U3;->a(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0
.end method

.method public final plus(Lo/H0;)Lo/H0;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Lo/W0;->g(Lo/H0;Lo/H0;)Lo/H0;

    move-result-object p1

    return-object p1
.end method

.method public q(Ljava/lang/Throwable;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public r(Lo/s0;)V
    .locals 0

    throw p1
.end method

.method public final s(Lo/O2;)V
    .locals 8

    sget-object v0, Lo/S3;->a:Lo/S3;

    sget-object v1, Lo/W2;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    if-nez p1, :cond_0

    invoke-virtual {v1, p0, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void

    :cond_0
    check-cast p1, Lo/W2;

    :goto_0
    invoke-virtual {p1}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v2

    instance-of v3, v2, Lo/o1;

    const/4 v4, 0x1

    const/4 v5, 0x0

    const/4 v6, -0x1

    sget-object v7, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    if-eqz v3, :cond_4

    move-object v3, v2

    check-cast v3, Lo/o1;

    iget-boolean v3, v3, Lo/o1;->a:Z

    if-eqz v3, :cond_1

    goto :goto_3

    :cond_1
    sget-object v3, Lo/F2;->h:Lo/o1;

    :cond_2
    invoke-virtual {v7, p1, v2, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :goto_1
    move v5, v4

    goto :goto_3

    :cond_3
    invoke-virtual {v7, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-eq v5, v2, :cond_2

    :goto_2
    move v5, v6

    goto :goto_3

    :cond_4
    instance-of v3, v2, Lo/t2;

    if-eqz v3, :cond_7

    move-object v3, v2

    check-cast v3, Lo/t2;

    iget-object v3, v3, Lo/t2;->a:Lo/R3;

    :cond_5
    invoke-virtual {v7, p1, v2, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_1

    :cond_6
    invoke-virtual {v7, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-eq v5, v2, :cond_5

    goto :goto_2

    :cond_7
    :goto_3
    if-eqz v5, :cond_8

    if-eq v5, v4, :cond_8

    goto :goto_0

    :cond_8
    new-instance v2, Lo/a0;

    invoke-direct {v2, p0}, Lo/a0;-><init>(Lo/W2;)V

    const/4 v3, 0x2

    invoke-static {p1, v4, v2, v3}, Lo/W0;->f(Lo/O2;ZLo/S2;I)Lo/k1;

    move-result-object p1

    check-cast p1, Lo/Z;

    invoke-virtual {v1, p0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v2

    instance-of v2, v2, Lo/u2;

    if-nez v2, :cond_9

    invoke-interface {p1}, Lo/k1;->dispose()V

    invoke-virtual {v1, p0, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_9
    return-void
.end method

.method public final t(ZZLo/E2;)Lo/k1;
    .locals 7

    const/4 v0, 0x0

    if-eqz p1, :cond_1

    instance-of v1, p3, Lo/Q2;

    if-eqz v1, :cond_0

    move-object v1, p3

    check-cast v1, Lo/Q2;

    goto :goto_0

    :cond_0
    move-object v1, v0

    :goto_0
    if-nez v1, :cond_4

    new-instance v1, Lo/K2;

    invoke-direct {v1, p3}, Lo/K2;-><init>(Lo/E2;)V

    goto :goto_2

    :cond_1
    instance-of v1, p3, Lo/S2;

    if-eqz v1, :cond_2

    move-object v1, p3

    check-cast v1, Lo/S2;

    goto :goto_1

    :cond_2
    move-object v1, v0

    :goto_1
    if-eqz v1, :cond_3

    goto :goto_2

    :cond_3
    new-instance v1, Lo/L2;

    invoke-direct {v1, p3}, Lo/L2;-><init>(Lo/E2;)V

    :cond_4
    :goto_2
    iput-object p0, v1, Lo/S2;->d:Lo/W2;

    :cond_5
    :goto_3
    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v2

    instance-of v3, v2, Lo/o1;

    if-eqz v3, :cond_c

    move-object v3, v2

    check-cast v3, Lo/o1;

    iget-boolean v4, v3, Lo/o1;->a:Z

    if-eqz v4, :cond_8

    sget-object v4, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_6
    invoke-virtual {v4, p0, v2, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_7

    goto/16 :goto_8

    :cond_7
    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, v2, :cond_6

    goto :goto_3

    :cond_8
    new-instance v2, Lo/R3;

    invoke-direct {v2}, Lo/t3;-><init>()V

    iget-boolean v4, v3, Lo/o1;->a:Z

    if-eqz v4, :cond_9

    move-object v4, v2

    goto :goto_4

    :cond_9
    new-instance v4, Lo/t2;

    invoke-direct {v4, v2}, Lo/t2;-><init>(Lo/R3;)V

    :cond_a
    :goto_4
    sget-object v2, Lo/W2;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v2, p0, v3, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_b

    goto :goto_3

    :cond_b
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-eq v2, v3, :cond_a

    goto :goto_3

    :cond_c
    instance-of v3, v2, Lo/u2;

    if-eqz v3, :cond_15

    move-object v3, v2

    check-cast v3, Lo/u2;

    invoke-interface {v3}, Lo/u2;->d()Lo/R3;

    move-result-object v3

    if-nez v3, :cond_d

    const-string v3, "null cannot be cast to non-null type kotlinx.coroutines.JobNode"

    invoke-static {v2, v3}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Lo/S2;

    invoke-virtual {p0, v2}, Lo/W2;->A(Lo/S2;)V

    goto :goto_3

    :cond_d
    sget-object v4, Lo/S3;->a:Lo/S3;

    if-eqz p1, :cond_12

    instance-of v5, v2, Lo/U2;

    if-eqz v5, :cond_12

    monitor-enter v2

    :try_start_0
    move-object v5, v2

    check-cast v5, Lo/U2;

    invoke-virtual {v5}, Lo/U2;->c()Ljava/lang/Throwable;

    move-result-object v5

    if-eqz v5, :cond_e

    instance-of v6, p3, Lo/a0;

    if-eqz v6, :cond_11

    move-object v6, v2

    check-cast v6, Lo/U2;

    invoke-virtual {v6}, Lo/U2;->f()Z

    move-result v6

    if-nez v6, :cond_11

    goto :goto_5

    :catchall_0
    move-exception p1

    goto :goto_6

    :cond_e
    :goto_5
    move-object v4, v2

    check-cast v4, Lo/u2;

    invoke-virtual {p0, v4, v3, v1}, Lo/W2;->c(Lo/u2;Lo/R3;Lo/S2;)Z

    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v4, :cond_f

    monitor-exit v2

    goto/16 :goto_3

    :cond_f
    if-nez v5, :cond_10

    monitor-exit v2

    return-object v1

    :cond_10
    move-object v4, v1

    :cond_11
    monitor-exit v2

    goto :goto_7

    :goto_6
    monitor-exit v2

    throw p1

    :cond_12
    move-object v5, v0

    :goto_7
    if-eqz v5, :cond_14

    if-eqz p2, :cond_13

    invoke-interface {p3, v5}, Lo/E2;->c(Ljava/lang/Throwable;)V

    :cond_13
    return-object v4

    :cond_14
    check-cast v2, Lo/u2;

    invoke-virtual {p0, v2, v3, v1}, Lo/W2;->c(Lo/u2;Lo/R3;Lo/S2;)Z

    move-result v2

    if-eqz v2, :cond_5

    :goto_8
    return-object v1

    :cond_15
    if-eqz p2, :cond_18

    instance-of p1, v2, Lo/q0;

    if-eqz p1, :cond_16

    check-cast v2, Lo/q0;

    goto :goto_9

    :cond_16
    move-object v2, v0

    :goto_9
    if-eqz v2, :cond_17

    iget-object v0, v2, Lo/q0;->a:Ljava/lang/Throwable;

    :cond_17
    invoke-interface {p3, v0}, Lo/E2;->c(Ljava/lang/Throwable;)V

    :cond_18
    sget-object p1, Lo/S3;->a:Lo/S3;

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v2, 0x7b

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v2}, Lo/W2;->B(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v2, 0x7d

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x40

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Lo/W0;->d(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public u()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final v(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    :cond_0
    invoke-virtual {p0}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0, v0, p1}, Lo/W2;->C(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Lo/F2;->b:Lo/Q;

    if-ne v0, v1, :cond_3

    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Job "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " is already complete or completing, but is being completed with "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    instance-of v2, p1, Lo/q0;

    const/4 v3, 0x0

    if-eqz v2, :cond_1

    check-cast p1, Lo/q0;

    goto :goto_0

    :cond_1
    move-object p1, v3

    :goto_0
    if-eqz p1, :cond_2

    iget-object v3, p1, Lo/q0;->a:Ljava/lang/Throwable;

    :cond_2
    invoke-direct {v0, v1, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_3
    sget-object v1, Lo/F2;->d:Lo/Q;

    if-eq v0, v1, :cond_0

    return-object v0
.end method

.method public final x(Lo/R3;Ljava/lang/Throwable;)V
    .locals 6

    invoke-virtual {p1}, Lo/t3;->g()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode{ kotlinx.coroutines.internal.LockFreeLinkedListKt.Node }"

    invoke-static {v0, v1}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Lo/t3;

    const/4 v1, 0x0

    :goto_0
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_2

    instance-of v2, v0, Lo/Q2;

    if-eqz v2, :cond_1

    move-object v2, v0

    check-cast v2, Lo/S2;

    :try_start_0
    invoke-interface {v2, p2}, Lo/E2;->c(Ljava/lang/Throwable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v3

    if-eqz v1, :cond_0

    invoke-static {v1, v3}, Lo/W0;->c(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    goto :goto_1

    :cond_0
    new-instance v1, Lo/s0;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Exception in completion handler "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " for "

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2, v3}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_1
    :goto_1
    invoke-virtual {v0}, Lo/t3;->h()Lo/t3;

    move-result-object v0

    goto :goto_0

    :cond_2
    if-eqz v1, :cond_3

    invoke-virtual {p0, v1}, Lo/W2;->r(Lo/s0;)V

    :cond_3
    invoke-virtual {p0, p2}, Lo/W2;->g(Ljava/lang/Throwable;)Z

    return-void
.end method

.method public y(Ljava/lang/Object;)V
    .locals 0

    return-void
.end method

.method public z()V
    .locals 0

    return-void
.end method

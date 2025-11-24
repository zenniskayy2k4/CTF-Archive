.class public final Lo/g1;
.super Lo/i1;
.source "SourceFile"

# interfaces
.implements Lo/R0;
.implements Lo/B0;


# static fields
.field public static final synthetic h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile synthetic _reusableCancellableContinuation$volatile:Ljava/lang/Object;

.field public final d:Lo/K0;

.field public final e:Lo/B0;

.field public f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-class v0, Ljava/lang/Object;

    const-string v1, "_reusableCancellableContinuation$volatile"

    const-class v2, Lo/g1;

    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/g1;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    return-void
.end method

.method public constructor <init>(Lo/K0;Lo/B0;)V
    .locals 1

    const/4 v0, -0x1

    invoke-direct {p0, v0}, Lo/i1;-><init>(I)V

    iput-object p1, p0, Lo/g1;->d:Lo/K0;

    iput-object p2, p0, Lo/g1;->e:Lo/B0;

    sget-object p1, Lo/G4;->a:Lo/Q;

    iput-object p1, p0, Lo/g1;->f:Ljava/lang/Object;

    invoke-interface {p2}, Lo/B0;->getContext()Lo/H0;

    move-result-object p1

    const/4 p2, 0x0

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    sget-object v0, Lo/m0;->f:Lo/m0;

    invoke-interface {p1, p2, v0}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Lo/F2;->c(Ljava/lang/Object;)V

    iput-object p1, p0, Lo/g1;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/util/concurrent/CancellationException;)V
    .locals 0

    instance-of p2, p1, Lo/r0;

    if-nez p2, :cond_0

    return-void

    :cond_0
    check-cast p1, Lo/r0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    throw p1
.end method

.method public final b()Lo/B0;
    .locals 0

    return-object p0
.end method

.method public final f()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Lo/g1;->f:Ljava/lang/Object;

    sget-object v1, Lo/G4;->a:Lo/Q;

    iput-object v1, p0, Lo/g1;->f:Ljava/lang/Object;

    return-object v0
.end method

.method public final getCallerFrame()Lo/R0;
    .locals 2

    iget-object v0, p0, Lo/g1;->e:Lo/B0;

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

    iget-object v0, p0, Lo/g1;->e:Lo/B0;

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v0

    return-object v0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 9

    iget-object v0, p0, Lo/g1;->e:Lo/B0;

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v1

    invoke-static {p1}, Lo/t4;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v2

    const/4 v3, 0x0

    if-nez v2, :cond_0

    move-object v4, p1

    goto :goto_0

    :cond_0
    new-instance v4, Lo/q0;

    invoke-direct {v4, v3, v2}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    :goto_0
    iget-object v2, p0, Lo/g1;->d:Lo/K0;

    invoke-virtual {v2, v1}, Lo/K0;->isDispatchNeeded(Lo/H0;)Z

    move-result v5

    if-eqz v5, :cond_1

    iput-object v4, p0, Lo/g1;->f:Ljava/lang/Object;

    iput v3, p0, Lo/i1;->c:I

    invoke-virtual {v2, v1, p0}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void

    :cond_1
    invoke-static {}, Lo/f5;->a()Lo/x1;

    move-result-object v1

    iget-wide v5, v1, Lo/x1;->a:J

    const-wide v7, 0x100000000L

    cmp-long v2, v5, v7

    if-ltz v2, :cond_3

    iput-object v4, p0, Lo/g1;->f:Ljava/lang/Object;

    iput v3, p0, Lo/i1;->c:I

    iget-object p1, v1, Lo/x1;->c:Lo/G;

    if-nez p1, :cond_2

    new-instance p1, Lo/G;

    invoke-direct {p1}, Lo/G;-><init>()V

    iput-object p1, v1, Lo/x1;->c:Lo/G;

    :cond_2
    invoke-virtual {p1, p0}, Lo/G;->addLast(Ljava/lang/Object;)V

    return-void

    :cond_3
    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Lo/x1;->d(Z)V

    :try_start_0
    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v2

    iget-object v3, p0, Lo/g1;->g:Ljava/lang/Object;

    invoke-static {v2, v3}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    invoke-interface {v0, p1}, Lo/B0;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-static {v2, v3}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    :cond_4
    invoke-virtual {v1}, Lo/x1;->e()Z

    move-result p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-nez p1, :cond_4

    :goto_1
    invoke-virtual {v1}, Lo/x1;->b()V

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_2

    :catchall_1
    move-exception p1

    :try_start_3
    invoke-static {v2, v3}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_2
    const/4 v0, 0x0

    :try_start_4
    invoke-virtual {p0, p1, v0}, Lo/i1;->e(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    goto :goto_1

    :goto_3
    return-void

    :catchall_2
    move-exception p1

    invoke-virtual {v1}, Lo/x1;->b()V

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "DispatchedContinuation["

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lo/g1;->d:Lo/K0;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Lo/g1;->e:Lo/B0;

    invoke-static {v1}, Lo/W0;->j(Lo/B0;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

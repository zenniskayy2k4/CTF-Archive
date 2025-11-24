.class public final Lo/l3;
.super Lo/K0;
.source "SourceFile"

# interfaces
.implements Lo/c1;


# static fields
.field public static final synthetic e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final a:Lo/K0;

.field public final b:I

.field public final c:Lo/u3;

.field public final d:Ljava/lang/Object;

.field private volatile synthetic runningWorkers$volatile:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Lo/l3;

    const-string v1, "runningWorkers$volatile"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/l3;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Lo/K0;I)V
    .locals 0

    invoke-direct {p0}, Lo/K0;-><init>()V

    iput-object p1, p0, Lo/l3;->a:Lo/K0;

    iput p2, p0, Lo/l3;->b:I

    instance-of p2, p1, Lo/c1;

    if-eqz p2, :cond_0

    check-cast p1, Lo/c1;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_1

    sget p1, Lo/Z0;->a:I

    :cond_1
    new-instance p1, Lo/u3;

    invoke-direct {p1}, Lo/u3;-><init>()V

    iput-object p1, p0, Lo/l3;->c:Lo/u3;

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/l3;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final b()Ljava/lang/Runnable;
    .locals 3

    :goto_0
    iget-object v0, p0, Lo/l3;->c:Lo/u3;

    invoke-virtual {v0}, Lo/u3;->d()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Runnable;

    if-nez v0, :cond_1

    iget-object v0, p0, Lo/l3;->d:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Lo/l3;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I

    iget-object v2, p0, Lo/l3;->c:Lo/u3;

    invoke-virtual {v2}, Lo/u3;->c()I

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v2, :cond_0

    monitor-exit v0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    :try_start_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->incrementAndGet(Ljava/lang/Object;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    goto :goto_0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1

    :cond_1
    return-object v0
.end method

.method public final c()Z
    .locals 4

    iget-object v0, p0, Lo/l3;->d:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Lo/l3;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v2

    iget v3, p0, Lo/l3;->b:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-lt v2, v3, :cond_0

    monitor-exit v0

    const/4 v0, 0x0

    return v0

    :cond_0
    :try_start_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->incrementAndGet(Ljava/lang/Object;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    const/4 v0, 0x1

    return v0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method

.method public final dispatch(Lo/H0;Ljava/lang/Runnable;)V
    .locals 0

    iget-object p1, p0, Lo/l3;->c:Lo/u3;

    invoke-virtual {p1, p2}, Lo/u3;->a(Ljava/lang/Runnable;)Z

    sget-object p1, Lo/l3;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p1

    iget p2, p0, Lo/l3;->b:I

    if-ge p1, p2, :cond_1

    invoke-virtual {p0}, Lo/l3;->c()Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Lo/l3;->b()Ljava/lang/Runnable;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance p2, Lo/k3;

    invoke-direct {p2, p0, p1}, Lo/k3;-><init>(Lo/l3;Ljava/lang/Runnable;)V

    iget-object p1, p0, Lo/l3;->a:Lo/K0;

    invoke-virtual {p1, p0, p2}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final dispatchYield(Lo/H0;Ljava/lang/Runnable;)V
    .locals 0

    iget-object p1, p0, Lo/l3;->c:Lo/u3;

    invoke-virtual {p1, p2}, Lo/u3;->a(Ljava/lang/Runnable;)Z

    sget-object p1, Lo/l3;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p1

    iget p2, p0, Lo/l3;->b:I

    if-ge p1, p2, :cond_1

    invoke-virtual {p0}, Lo/l3;->c()Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Lo/l3;->b()Ljava/lang/Runnable;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance p2, Lo/k3;

    invoke-direct {p2, p0, p1}, Lo/k3;-><init>(Lo/l3;Ljava/lang/Runnable;)V

    iget-object p1, p0, Lo/l3;->a:Lo/K0;

    invoke-virtual {p1, p0, p2}, Lo/K0;->dispatchYield(Lo/H0;Ljava/lang/Runnable;)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final limitedParallelism(I)Lo/K0;
    .locals 1

    invoke-static {p1}, Lo/G4;->d(I)V

    iget v0, p0, Lo/l3;->b:I

    if-lt p1, v0, :cond_0

    return-object p0

    :cond_0
    invoke-super {p0, p1}, Lo/K0;->limitedParallelism(I)Lo/K0;

    move-result-object p1

    return-object p1
.end method

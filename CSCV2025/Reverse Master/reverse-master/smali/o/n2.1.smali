.class public final Lo/n2;
.super Lo/K0;
.source "SourceFile"

# interfaces
.implements Lo/c1;


# instance fields
.field public final a:Landroid/os/Handler;

.field public final b:Z

.field public final c:Lo/n2;


# direct methods
.method public constructor <init>(Landroid/os/Handler;Z)V
    .locals 1

    invoke-direct {p0}, Lo/K0;-><init>()V

    iput-object p1, p0, Lo/n2;->a:Landroid/os/Handler;

    iput-boolean p2, p0, Lo/n2;->b:Z

    if-eqz p2, :cond_0

    move-object p2, p0

    goto :goto_0

    :cond_0
    new-instance p2, Lo/n2;

    const/4 v0, 0x1

    invoke-direct {p2, p1, v0}, Lo/n2;-><init>(Landroid/os/Handler;Z)V

    :goto_0
    iput-object p2, p0, Lo/n2;->c:Lo/n2;

    return-void
.end method


# virtual methods
.method public final dispatch(Lo/H0;Ljava/lang/Runnable;)V
    .locals 3

    iget-object v0, p0, Lo/n2;->a:Landroid/os/Handler;

    invoke-virtual {v0, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    move-result v0

    if-nez v0, :cond_1

    new-instance v0, Ljava/util/concurrent/CancellationException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "The task was rejected, the handler underlying the dispatcher \'"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\' was closed"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    sget-object v1, Lo/D0;->c:Lo/D0;

    invoke-interface {p1, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v1

    check-cast v1, Lo/O2;

    if-eqz v1, :cond_0

    check-cast v1, Lo/W2;

    invoke-virtual {v1, v0}, Lo/W2;->f(Ljava/lang/Object;)Z

    :cond_0
    sget-object v0, Lo/j1;->b:Lo/a1;

    invoke-virtual {v0, p1, p2}, Lo/a1;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    :cond_1
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Lo/n2;

    if-eqz v0, :cond_0

    check-cast p1, Lo/n2;

    iget-object v0, p1, Lo/n2;->a:Landroid/os/Handler;

    iget-object v1, p0, Lo/n2;->a:Landroid/os/Handler;

    if-ne v0, v1, :cond_0

    iget-boolean p1, p1, Lo/n2;->b:Z

    iget-boolean v0, p0, Lo/n2;->b:Z

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Lo/n2;->a:Landroid/os/Handler;

    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v0

    iget-boolean v1, p0, Lo/n2;->b:Z

    if-eqz v1, :cond_0

    const/16 v1, 0x4cf

    goto :goto_0

    :cond_0
    const/16 v1, 0x4d5

    :goto_0
    xor-int/2addr v0, v1

    return v0
.end method

.method public final isDispatchNeeded(Lo/H0;)Z
    .locals 1

    iget-boolean p1, p0, Lo/n2;->b:Z

    if-eqz p1, :cond_1

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object p1

    iget-object v0, p0, Lo/n2;->a:Landroid/os/Handler;

    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-static {p1, v0}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public limitedParallelism(I)Lo/K0;
    .locals 0

    invoke-static {p1}, Lo/G4;->d(I)V

    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    sget-object v0, Lo/j1;->a:Lo/b1;

    sget-object v0, Lo/A3;->a:Lo/n2;

    if-ne p0, v0, :cond_0

    const-string v0, "Dispatchers.Main"

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    :try_start_0
    iget-object v0, v0, Lo/n2;->c:Lo/n2;
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-object v0, v1

    :goto_0
    if-ne p0, v0, :cond_1

    const-string v0, "Dispatchers.Main.immediate"

    goto :goto_1

    :cond_1
    move-object v0, v1

    :goto_1
    if-nez v0, :cond_2

    iget-object v0, p0, Lo/n2;->a:Landroid/os/Handler;

    invoke-virtual {v0}, Landroid/os/Handler;->toString()Ljava/lang/String;

    move-result-object v0

    iget-boolean v1, p0, Lo/n2;->b:Z

    if-eqz v1, :cond_2

    const-string v1, ".immediate"

    invoke-static {v0, v1}, Lo/l;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :cond_2
    return-object v0
.end method

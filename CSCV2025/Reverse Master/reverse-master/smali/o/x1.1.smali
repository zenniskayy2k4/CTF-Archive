.class public abstract Lo/x1;
.super Lo/K0;
.source "SourceFile"


# instance fields
.field public a:J

.field public b:Z

.field public c:Lo/G;


# virtual methods
.method public final b()V
    .locals 4

    iget-wide v0, p0, Lo/x1;->a:J

    const-wide v2, 0x100000000L

    sub-long/2addr v0, v2

    iput-wide v0, p0, Lo/x1;->a:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-lez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-boolean v0, p0, Lo/x1;->b:Z

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Lo/x1;->f()V

    :cond_1
    :goto_0
    return-void
.end method

.method public abstract c()Ljava/lang/Thread;
.end method

.method public final d(Z)V
    .locals 4

    iget-wide v0, p0, Lo/x1;->a:J

    if-eqz p1, :cond_0

    const-wide v2, 0x100000000L

    goto :goto_0

    :cond_0
    const-wide/16 v2, 0x1

    :goto_0
    add-long/2addr v2, v0

    iput-wide v2, p0, Lo/x1;->a:J

    if-nez p1, :cond_1

    const/4 p1, 0x1

    iput-boolean p1, p0, Lo/x1;->b:Z

    :cond_1
    return-void
.end method

.method public final e()Z
    .locals 3

    iget-object v0, p0, Lo/x1;->c:Lo/G;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return v1

    :cond_0
    invoke-virtual {v0}, Lo/G;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_1

    const/4 v0, 0x0

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Lo/G;->removeFirst()Ljava/lang/Object;

    move-result-object v0

    :goto_0
    check-cast v0, Lo/i1;

    if-nez v0, :cond_2

    return v1

    :cond_2
    invoke-virtual {v0}, Lo/i1;->run()V

    const/4 v0, 0x1

    return v0
.end method

.method public abstract f()V
.end method

.method public final limitedParallelism(I)Lo/K0;
    .locals 0

    invoke-static {p1}, Lo/G4;->d(I)V

    return-object p0
.end method

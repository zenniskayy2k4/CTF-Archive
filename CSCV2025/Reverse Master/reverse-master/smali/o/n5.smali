.class public final Lo/n5;
.super Lo/w4;
.source "SourceFile"


# instance fields
.field public final e:Ljava/lang/ThreadLocal;

.field private volatile threadLocalIsSet:Z


# direct methods
.method public constructor <init>(Lo/B0;Lo/H0;)V
    .locals 2

    sget-object v0, Lo/o5;->a:Lo/o5;

    invoke-interface {p2, v0}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-interface {p2, v0}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object v0

    goto :goto_0

    :cond_0
    move-object v0, p2

    :goto_0
    invoke-direct {p0, p1, v0}, Lo/w4;-><init>(Lo/B0;Lo/H0;)V

    new-instance v0, Ljava/lang/ThreadLocal;

    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    iput-object v0, p0, Lo/n5;->e:Ljava/lang/ThreadLocal;

    invoke-interface {p1}, Lo/B0;->getContext()Lo/H0;

    move-result-object p1

    sget-object v0, Lo/D0;->a:Lo/D0;

    invoke-interface {p1, v0}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object p1

    instance-of p1, p1, Lo/K0;

    if-nez p1, :cond_1

    const/4 p1, 0x0

    invoke-static {p2, p1}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p2, p1}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    invoke-virtual {p0, p2, p1}, Lo/n5;->E(Lo/H0;Ljava/lang/Object;)V

    :cond_1
    return-void
.end method


# virtual methods
.method public final D()Z
    .locals 3

    iget-boolean v0, p0, Lo/n5;->threadLocalIsSet:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iget-object v0, p0, Lo/n5;->e:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iget-object v2, p0, Lo/n5;->e:Ljava/lang/ThreadLocal;

    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->remove()V

    xor-int/2addr v0, v1

    return v0
.end method

.method public final E(Lo/H0;Ljava/lang/Object;)V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Lo/n5;->threadLocalIsSet:Z

    iget-object v0, p0, Lo/n5;->e:Ljava/lang/ThreadLocal;

    new-instance v1, Lo/W3;

    invoke-direct {v1, p1, p2}, Lo/W3;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    return-void
.end method

.method public final e(Ljava/lang/Object;)V
    .locals 5

    iget-boolean v0, p0, Lo/n5;->threadLocalIsSet:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Lo/n5;->e:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/W3;

    if-eqz v0, :cond_0

    iget-object v1, v0, Lo/W3;->a:Ljava/lang/Object;

    check-cast v1, Lo/H0;

    iget-object v0, v0, Lo/W3;->b:Ljava/lang/Object;

    invoke-static {v1, v0}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    :cond_0
    iget-object v0, p0, Lo/n5;->e:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->remove()V

    :cond_1
    invoke-static {p1}, Lo/G4;->h(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Lo/w4;->d:Lo/B0;

    invoke-interface {v0}, Lo/B0;->getContext()Lo/H0;

    move-result-object v1

    const/4 v2, 0x0

    invoke-static {v1, v2}, Lo/G4;->n(Lo/H0;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Lo/G4;->d:Lo/Q;

    if-eq v3, v4, :cond_2

    invoke-static {v0, v1, v3}, Lo/G4;->o(Lo/B0;Lo/H0;Ljava/lang/Object;)Lo/n5;

    move-result-object v2

    :cond_2
    :try_start_0
    iget-object v0, p0, Lo/w4;->d:Lo/B0;

    invoke-interface {v0, p1}, Lo/B0;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v2, :cond_4

    invoke-virtual {v2}, Lo/n5;->D()Z

    move-result p1

    if-eqz p1, :cond_3

    goto :goto_0

    :cond_3
    return-void

    :cond_4
    :goto_0
    invoke-static {v1, v3}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception p1

    if-eqz v2, :cond_5

    invoke-virtual {v2}, Lo/n5;->D()Z

    move-result v0

    if-eqz v0, :cond_6

    :cond_5
    invoke-static {v1, v3}, Lo/G4;->i(Lo/H0;Ljava/lang/Object;)V

    :cond_6
    throw p1
.end method

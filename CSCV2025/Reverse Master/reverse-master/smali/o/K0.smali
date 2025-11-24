.class public abstract Lo/K0;
.super Lo/d;
.source "SourceFile"

# interfaces
.implements Lo/E0;


# static fields
.field public static final Key:Lo/J0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Lo/J0;

    sget-object v1, Lo/D0;->a:Lo/D0;

    sget-object v2, Lo/I0;->a:Lo/I0;

    invoke-direct {v0, v1, v2}, Lo/J0;-><init>(Lo/G0;Lo/S1;)V

    sput-object v0, Lo/K0;->Key:Lo/J0;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    sget-object v0, Lo/D0;->a:Lo/D0;

    invoke-direct {p0, v0}, Lo/d;-><init>(Lo/G0;)V

    return-void
.end method


# virtual methods
.method public abstract dispatch(Lo/H0;Ljava/lang/Runnable;)V
.end method

.method public dispatchYield(Lo/H0;Ljava/lang/Runnable;)V
    .locals 0

    invoke-virtual {p0, p1, p2}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void
.end method

.method public get(Lo/G0;)Lo/F0;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E::",
            "Lo/F0;",
            ">(",
            "Lo/G0;",
            ")TE;"
        }
    .end annotation

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v1, p1, Lo/J0;

    if-eqz v1, :cond_1

    check-cast p1, Lo/J0;

    invoke-interface {p0}, Lo/F0;->getKey()Lo/G0;

    move-result-object v1

    invoke-static {v1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    if-eq v1, p1, :cond_0

    iget-object v0, p1, Lo/J0;->b:Lo/G0;

    if-ne v0, v1, :cond_2

    :cond_0
    iget-object p1, p1, Lo/J0;->a:Lo/h3;

    invoke-interface {p1, p0}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lo/F0;

    if-eqz p1, :cond_2

    return-object p1

    :cond_1
    sget-object v0, Lo/D0;->a:Lo/D0;

    if-ne v0, p1, :cond_2

    return-object p0

    :cond_2
    const/4 p1, 0x0

    return-object p1
.end method

.method public final interceptContinuation(Lo/B0;)Lo/B0;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lo/B0;",
            ")",
            "Lo/B0;"
        }
    .end annotation

    new-instance v0, Lo/g1;

    invoke-direct {v0, p0, p1}, Lo/g1;-><init>(Lo/K0;Lo/B0;)V

    return-object v0
.end method

.method public isDispatchNeeded(Lo/H0;)Z
    .locals 0

    instance-of p1, p0, Lo/m5;

    xor-int/lit8 p1, p1, 0x1

    return p1
.end method

.method public limitedParallelism(I)Lo/K0;
    .locals 1

    invoke-static {p1}, Lo/G4;->d(I)V

    new-instance v0, Lo/l3;

    invoke-direct {v0, p0, p1}, Lo/l3;-><init>(Lo/K0;I)V

    return-object v0
.end method

.method public minusKey(Lo/G0;)Lo/H0;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/G0;",
            ")",
            "Lo/H0;"
        }
    .end annotation

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v1, p1, Lo/J0;

    sget-object v2, Lo/p1;->a:Lo/p1;

    if-eqz v1, :cond_2

    check-cast p1, Lo/J0;

    invoke-interface {p0}, Lo/F0;->getKey()Lo/G0;

    move-result-object v1

    invoke-static {v1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    if-eq v1, p1, :cond_1

    iget-object v0, p1, Lo/J0;->b:Lo/G0;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    return-object p0

    :cond_1
    :goto_0
    iget-object p1, p1, Lo/J0;->a:Lo/h3;

    invoke-interface {p1, p0}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lo/F0;

    if-eqz p1, :cond_3

    goto :goto_1

    :cond_2
    sget-object v0, Lo/D0;->a:Lo/D0;

    if-ne v0, p1, :cond_3

    :goto_1
    return-object v2

    :cond_3
    return-object p0
.end method

.method public final plus(Lo/K0;)Lo/K0;
    .locals 0

    return-object p1
.end method

.method public final releaseInterceptedContinuation(Lo/B0;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/B0;",
            ")V"
        }
    .end annotation

    const-string v0, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<*>"

    invoke-static {p1, v0}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Lo/g1;

    :cond_0
    sget-object v0, Lo/g1;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Lo/G4;->b:Lo/Q;

    if-eq v1, v2, :cond_0

    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    instance-of v0, p1, Lo/U;

    if-eqz v0, :cond_1

    check-cast p1, Lo/U;

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_3

    sget-object v0, Lo/U;->h:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/k1;

    if-nez v1, :cond_2

    goto :goto_1

    :cond_2
    invoke-interface {v1}, Lo/k1;->dispose()V

    sget-object v1, Lo/S3;->a:Lo/S3;

    invoke-virtual {v0, p1, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_3
    :goto_1
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

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

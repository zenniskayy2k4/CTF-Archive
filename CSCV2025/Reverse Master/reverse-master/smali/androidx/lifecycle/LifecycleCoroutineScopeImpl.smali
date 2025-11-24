.class public final Landroidx/lifecycle/LifecycleCoroutineScopeImpl;
.super Landroidx/lifecycle/LifecycleCoroutineScope;
.source "SourceFile"

# interfaces
.implements Landroidx/lifecycle/LifecycleEventObserver;


# instance fields
.field private final coroutineContext:Lo/H0;

.field private final lifecycle:Landroidx/lifecycle/Lifecycle;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/Lifecycle;Lo/H0;)V
    .locals 2

    const-string v0, "lifecycle"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "coroutineContext"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Landroidx/lifecycle/LifecycleCoroutineScope;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->lifecycle:Landroidx/lifecycle/Lifecycle;

    iput-object p2, p0, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->coroutineContext:Lo/H0;

    invoke-virtual {p0}, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->getLifecycle$lifecycle_common()Landroidx/lifecycle/Lifecycle;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/lifecycle/Lifecycle;->getCurrentState()Landroidx/lifecycle/Lifecycle$State;

    move-result-object p1

    sget-object p2, Landroidx/lifecycle/Lifecycle$State;->DESTROYED:Landroidx/lifecycle/Lifecycle$State;

    if-ne p1, p2, :cond_0

    invoke-virtual {p0}, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->getCoroutineContext()Lo/H0;

    move-result-object p1

    sget-object p2, Lo/D0;->c:Lo/D0;

    invoke-interface {p1, p2}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object p1

    check-cast p1, Lo/O2;

    if-eqz p1, :cond_0

    check-cast p1, Lo/W2;

    new-instance p2, Lo/P2;

    invoke-virtual {p1}, Lo/W2;->h()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    invoke-direct {p2, v0, v1, p1}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    invoke-virtual {p1, p2}, Lo/W2;->f(Ljava/lang/Object;)Z

    :cond_0
    return-void
.end method


# virtual methods
.method public getCoroutineContext()Lo/H0;
    .locals 1

    iget-object v0, p0, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->coroutineContext:Lo/H0;

    return-object v0
.end method

.method public getLifecycle$lifecycle_common()Landroidx/lifecycle/Lifecycle;
    .locals 1

    iget-object v0, p0, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->lifecycle:Landroidx/lifecycle/Lifecycle;

    return-object v0
.end method

.method public onStateChanged(Landroidx/lifecycle/LifecycleOwner;Landroidx/lifecycle/Lifecycle$Event;)V
    .locals 2

    const-string v0, "source"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "event"

    invoke-static {p2, p1}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->getLifecycle$lifecycle_common()Landroidx/lifecycle/Lifecycle;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/lifecycle/Lifecycle;->getCurrentState()Landroidx/lifecycle/Lifecycle$State;

    move-result-object p1

    sget-object p2, Landroidx/lifecycle/Lifecycle$State;->DESTROYED:Landroidx/lifecycle/Lifecycle$State;

    invoke-virtual {p1, p2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result p1

    if-gtz p1, :cond_0

    invoke-virtual {p0}, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->getLifecycle$lifecycle_common()Landroidx/lifecycle/Lifecycle;

    move-result-object p1

    invoke-virtual {p1, p0}, Landroidx/lifecycle/Lifecycle;->removeObserver(Landroidx/lifecycle/LifecycleObserver;)V

    invoke-virtual {p0}, Landroidx/lifecycle/LifecycleCoroutineScopeImpl;->getCoroutineContext()Lo/H0;

    move-result-object p1

    sget-object p2, Lo/D0;->c:Lo/D0;

    invoke-interface {p1, p2}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object p1

    check-cast p1, Lo/O2;

    if-eqz p1, :cond_0

    check-cast p1, Lo/W2;

    new-instance p2, Lo/P2;

    invoke-virtual {p1}, Lo/W2;->h()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    invoke-direct {p2, v0, v1, p1}, Lo/P2;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Lo/W2;)V

    invoke-virtual {p1, p2}, Lo/W2;->f(Ljava/lang/Object;)Z

    :cond_0
    return-void
.end method

.method public final register()V
    .locals 3

    sget-object v0, Lo/j1;->a:Lo/b1;

    sget-object v0, Lo/A3;->a:Lo/n2;

    iget-object v0, v0, Lo/n2;->c:Lo/n2;

    new-instance v1, Landroidx/lifecycle/LifecycleCoroutineScopeImpl$register$1;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Landroidx/lifecycle/LifecycleCoroutineScopeImpl$register$1;-><init>(Landroidx/lifecycle/LifecycleCoroutineScopeImpl;Lo/B0;)V

    const/4 v2, 0x2

    invoke-static {p0, v0, v1, v2}, Lo/G4;->g(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/n2;Lo/W1;I)Lo/M4;

    return-void
.end method

.class public abstract Landroidx/lifecycle/LifecycleCoroutineScope;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/P0;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public abstract synthetic getCoroutineContext()Lo/H0;
.end method

.method public abstract getLifecycle$lifecycle_common()Landroidx/lifecycle/Lifecycle;
.end method

.method public final launchWhenCreated(Lo/W1;)Lo/O2;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/W1;",
            ")",
            "Lo/O2;"
        }
    .end annotation

    const-string v0, "block"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/lifecycle/LifecycleCoroutineScope$launchWhenCreated$1;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Landroidx/lifecycle/LifecycleCoroutineScope$launchWhenCreated$1;-><init>(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/W1;Lo/B0;)V

    const/4 p1, 0x3

    invoke-static {p0, v1, v0, p1}, Lo/G4;->g(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/n2;Lo/W1;I)Lo/M4;

    move-result-object p1

    return-object p1
.end method

.method public final launchWhenResumed(Lo/W1;)Lo/O2;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/W1;",
            ")",
            "Lo/O2;"
        }
    .end annotation

    const-string v0, "block"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/lifecycle/LifecycleCoroutineScope$launchWhenResumed$1;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Landroidx/lifecycle/LifecycleCoroutineScope$launchWhenResumed$1;-><init>(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/W1;Lo/B0;)V

    const/4 p1, 0x3

    invoke-static {p0, v1, v0, p1}, Lo/G4;->g(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/n2;Lo/W1;I)Lo/M4;

    move-result-object p1

    return-object p1
.end method

.method public final launchWhenStarted(Lo/W1;)Lo/O2;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/W1;",
            ")",
            "Lo/O2;"
        }
    .end annotation

    const-string v0, "block"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/lifecycle/LifecycleCoroutineScope$launchWhenStarted$1;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Landroidx/lifecycle/LifecycleCoroutineScope$launchWhenStarted$1;-><init>(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/W1;Lo/B0;)V

    const/4 p1, 0x3

    invoke-static {p0, v1, v0, p1}, Lo/G4;->g(Landroidx/lifecycle/LifecycleCoroutineScope;Lo/n2;Lo/W1;I)Lo/M4;

    move-result-object p1

    return-object p1
.end method

.class final Landroidx/core/os/Profiling$registerForAllProfilingResults$1;
.super Lo/X4;
.source "SourceFile"

# interfaces
.implements Lo/W1;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/core/os/Profiling;->registerForAllProfilingResults(Landroid/content/Context;)Lo/D1;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lo/X4;",
        "Lo/W1;"
    }
.end annotation

.annotation runtime Lo/V0;
    c = "androidx.core.os.Profiling$registerForAllProfilingResults$1"
    f = "Profiling.kt"
    l = {
        0x4f
    }
    m = "invokeSuspend"
.end annotation


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Lo/B0;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Lo/B0;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->$context:Landroid/content/Context;

    invoke-direct {p0, p2}, Lo/X4;-><init>(Lo/B0;)V

    return-void
.end method

.method public static synthetic b(Ljava/lang/Runnable;)V
    .locals 0

    invoke-static {p0}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->invokeSuspend$lambda$1(Ljava/lang/Runnable;)V

    return-void
.end method

.method public static synthetic c(Landroid/os/ProfilingResult;)V
    .locals 1

    const/4 v0, 0x0

    invoke-static {v0, p0}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->invokeSuspend$lambda$0(Lo/c4;Landroid/os/ProfilingResult;)V

    return-void
.end method

.method public static synthetic d(Landroid/os/ProfilingManager;Landroidx/core/os/a;)Lo/p5;
    .locals 0

    invoke-static {p0, p1}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->invokeSuspend$lambda$2(Landroid/os/ProfilingManager;Ljava/util/function/Consumer;)Lo/p5;

    move-result-object p0

    return-object p0
.end method

.method private static final invokeSuspend$lambda$0(Lo/c4;Landroid/os/ProfilingResult;)V
    .locals 0

    invoke-static {p1}, Lo/F2;->c(Ljava/lang/Object;)V

    invoke-interface {p0}, Lo/c4;->b()Ljava/lang/Object;

    return-void
.end method

.method private static final invokeSuspend$lambda$1(Ljava/lang/Runnable;)V
    .locals 0

    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    return-void
.end method

.method private static final invokeSuspend$lambda$2(Landroid/os/ProfilingManager;Ljava/util/function/Consumer;)Lo/p5;
    .locals 0

    invoke-static {p0, p1}, Lo/f4;->f(Landroid/os/ProfilingManager;Ljava/util/function/Consumer;)V

    sget-object p0, Lo/p5;->a:Lo/p5;

    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lo/B0;)Lo/B0;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lo/B0;",
            ")",
            "Lo/B0;"
        }
    .end annotation

    new-instance v0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;

    iget-object v1, p0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->$context:Landroid/content/Context;

    invoke-direct {v0, v1, p2}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;-><init>(Landroid/content/Context;Lo/B0;)V

    iput-object p1, v0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    check-cast p2, Lo/B0;

    const/4 p1, 0x0

    invoke-virtual {p0, p1, p2}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->invoke(Lo/c4;Lo/B0;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

.method public final invoke(Lo/c4;Lo/B0;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/c4;",
            "Lo/B0;",
            ")",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->create(Ljava/lang/Object;Lo/B0;)Lo/B0;

    move-result-object p1

    check-cast p1, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;

    sget-object p2, Lo/p5;->a:Lo/p5;

    invoke-virtual {p1, p2}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Lo/Q0;->a:Lo/Q0;

    iget v1, p0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->label:I

    sget-object v2, Lo/p5;->a:Lo/p5;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Lo/F2;->q(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Lo/F2;->q(Ljava/lang/Object;)V

    iget-object p1, p0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->L$0:Ljava/lang/Object;

    if-nez p1, :cond_3

    new-instance p1, Landroidx/core/os/a;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iget-object v1, p0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->$context:Landroid/content/Context;

    invoke-static {}, Lo/f4;->b()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v1, v4}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Lo/f4;->a(Ljava/lang/Object;)Landroid/os/ProfilingManager;

    move-result-object v1

    new-instance v4, Landroidx/core/os/b;

    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    invoke-static {v1, v4, p1}, Lo/f4;->d(Landroid/os/ProfilingManager;Landroidx/core/os/b;Landroidx/core/os/a;)V

    new-instance v4, Landroidx/core/os/c;

    invoke-direct {v4, v1, p1}, Landroidx/core/os/c;-><init>(Landroid/os/ProfilingManager;Landroidx/core/os/a;)V

    iput v3, p0, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->label:I

    invoke-static {v4, p0}, Lo/G4;->a(Landroidx/core/os/c;Lo/C0;)Ljava/lang/Object;

    if-ne v2, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    return-object v2

    :cond_3
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

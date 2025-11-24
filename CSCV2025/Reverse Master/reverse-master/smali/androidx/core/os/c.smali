.class public final synthetic Landroidx/core/os/c;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/H1;


# instance fields
.field public final synthetic a:Landroid/os/ProfilingManager;

.field public final synthetic b:Landroidx/core/os/a;


# direct methods
.method public synthetic constructor <init>(Landroid/os/ProfilingManager;Landroidx/core/os/a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/core/os/c;->a:Landroid/os/ProfilingManager;

    iput-object p2, p0, Landroidx/core/os/c;->b:Landroidx/core/os/a;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Landroidx/core/os/c;->a:Landroid/os/ProfilingManager;

    iget-object v1, p0, Landroidx/core/os/c;->b:Landroidx/core/os/a;

    invoke-static {v0, v1}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->d(Landroid/os/ProfilingManager;Landroidx/core/os/a;)Lo/p5;

    move-result-object v0

    return-object v0
.end method

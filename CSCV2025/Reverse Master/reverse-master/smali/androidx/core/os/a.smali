.class public final synthetic Landroidx/core/os/a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/function/Consumer;


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Landroid/os/ProfilingResult;

    invoke-static {p1}, Landroidx/core/os/Profiling$registerForAllProfilingResults$1;->c(Landroid/os/ProfilingResult;)V

    return-void
.end method

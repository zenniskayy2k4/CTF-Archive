.class public final Lo/k3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public a:Ljava/lang/Runnable;

.field public final synthetic b:Lo/l3;


# direct methods
.method public constructor <init>(Lo/l3;Ljava/lang/Runnable;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/k3;->b:Lo/l3;

    iput-object p2, p0, Lo/k3;->a:Ljava/lang/Runnable;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    const/4 v0, 0x0

    :cond_0
    :try_start_0
    iget-object v1, p0, Lo/k3;->a:Ljava/lang/Runnable;

    invoke-interface {v1}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    sget-object v2, Lo/p1;->a:Lo/p1;

    invoke-static {v2, v1}, Lo/F2;->k(Lo/H0;Ljava/lang/Throwable;)V

    :goto_0
    iget-object v1, p0, Lo/k3;->b:Lo/l3;

    invoke-virtual {v1}, Lo/l3;->b()Ljava/lang/Runnable;

    move-result-object v2

    if-nez v2, :cond_1

    return-void

    :cond_1
    iput-object v2, p0, Lo/k3;->a:Ljava/lang/Runnable;

    add-int/lit8 v0, v0, 0x1

    const/16 v2, 0x10

    if-lt v0, v2, :cond_0

    iget-object v2, v1, Lo/l3;->a:Lo/K0;

    invoke-virtual {v2, v1}, Lo/K0;->isDispatchNeeded(Lo/H0;)Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v2, v1, p0}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void
.end method

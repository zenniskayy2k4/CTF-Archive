.class public abstract Lo/L0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    :try_start_0
    new-instance v0, Lo/u;

    invoke-direct {v0}, Lo/u;-><init>()V

    filled-new-array {v0}, [Lo/u;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const-string v1, "<this>"

    invoke-static {v0, v1}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Lo/C1;

    const/4 v2, 0x2

    invoke-direct {v1, v2, v0}, Lo/C1;-><init>(ILjava/lang/Object;)V

    new-instance v0, Lo/y0;

    invoke-direct {v0, v1}, Lo/y0;-><init>(Lo/C1;)V

    invoke-static {v0}, Lo/F4;->t(Lo/C4;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Lo/L0;->a:Ljava/util/List;

    return-void

    :catchall_0
    move-exception v0

    new-instance v1, Ljava/util/ServiceConfigurationError;

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2, v0}, Ljava/util/ServiceConfigurationError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v1
.end method

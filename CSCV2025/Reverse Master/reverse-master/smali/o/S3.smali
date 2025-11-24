.class public final Lo/S3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/k1;
.implements Lo/Z;


# static fields
.field public static final a:Lo/S3;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lo/S3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Lo/S3;->a:Lo/S3;

    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Throwable;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final dispose()V
    .locals 0

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "NonDisposableHandle"

    return-object v0
.end method

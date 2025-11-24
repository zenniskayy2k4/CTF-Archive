.class public final Landroidx/core/flagging/AconfigPackageCompat$Companion;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/core/flagging/AconfigPackageCompat;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation


# static fields
.field static final synthetic $$INSTANCE:Landroidx/core/flagging/AconfigPackageCompat$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/core/flagging/AconfigPackageCompat$Companion;

    invoke-direct {v0}, Landroidx/core/flagging/AconfigPackageCompat$Companion;-><init>()V

    sput-object v0, Landroidx/core/flagging/AconfigPackageCompat$Companion;->$$INSTANCE:Landroidx/core/flagging/AconfigPackageCompat$Companion;

    return-void
.end method

.method private constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final load(Ljava/lang/String;)Landroidx/core/flagging/AconfigPackageCompat;
    .locals 2

    const-string v0, "packageName"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x24

    if-lt v0, v1, :cond_1

    :try_start_0
    new-instance v0, Landroidx/core/flagging/AconfigPackageCompatApi36Impl;

    invoke-static {p1}, Lo/q;->d(Ljava/lang/String;)Landroid/os/flagging/AconfigPackage;

    move-result-object p1

    const-string v1, "load(...)"

    invoke-static {p1, v1}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, p1}, Landroidx/core/flagging/AconfigPackageCompatApi36Impl;-><init>(Landroid/os/flagging/AconfigPackage;)V
    :try_end_0
    .catch Landroid/os/flagging/AconfigStorageReadException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p1

    invoke-static {p1}, Lo/q;->a(Landroid/os/flagging/AconfigStorageReadException;)I

    move-result v0

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    new-instance p1, Landroidx/core/flagging/AconfigPackageCompatNoopImpl;

    invoke-direct {p1}, Landroidx/core/flagging/AconfigPackageCompatNoopImpl;-><init>()V

    return-object p1

    :cond_0
    throw p1

    :cond_1
    new-instance p1, Landroidx/core/flagging/AconfigPackageCompatNoopImpl;

    invoke-direct {p1}, Landroidx/core/flagging/AconfigPackageCompatNoopImpl;-><init>()V

    return-object p1
.end method

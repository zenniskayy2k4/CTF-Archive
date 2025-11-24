.class final Landroidx/core/flagging/AconfigPackageCompatApi36Impl;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/core/flagging/AconfigPackageCompat;


# annotations
.annotation build Landroidx/annotation/RequiresApi;
    value = 0x24
.end annotation


# instance fields
.field private final aconfigPackageImpl:Landroid/os/flagging/AconfigPackage;


# direct methods
.method public constructor <init>(Landroid/os/flagging/AconfigPackage;)V
    .locals 1

    const-string v0, "aconfigPackageImpl"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/core/flagging/AconfigPackageCompatApi36Impl;->aconfigPackageImpl:Landroid/os/flagging/AconfigPackage;

    return-void
.end method


# virtual methods
.method public getBooleanFlagValue(Ljava/lang/String;Z)Z
    .locals 1

    const-string v0, "flagName"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/core/flagging/AconfigPackageCompatApi36Impl;->aconfigPackageImpl:Landroid/os/flagging/AconfigPackage;

    invoke-virtual {v0, p1, p2}, Landroid/os/flagging/AconfigPackage;->getBooleanFlagValue(Ljava/lang/String;Z)Z

    move-result p1

    return p1
.end method

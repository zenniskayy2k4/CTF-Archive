.class public abstract synthetic Lo/q;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static bridge synthetic a(Landroid/os/flagging/AconfigStorageReadException;)I
    .locals 0

    invoke-virtual {p0}, Landroid/os/flagging/AconfigStorageReadException;->getErrorCode()I

    move-result p0

    return p0
.end method

.method public static synthetic b()Landroid/app/Notification$ProgressStyle;
    .locals 1

    new-instance v0, Landroid/app/Notification$ProgressStyle;

    invoke-direct {v0}, Landroid/app/Notification$ProgressStyle;-><init>()V

    return-object v0
.end method

.method public static bridge synthetic c(Ljava/lang/Object;)Landroid/os/flagging/AconfigPackage;
    .locals 0

    check-cast p0, Landroid/os/flagging/AconfigPackage;

    return-object p0
.end method

.method public static bridge synthetic d(Ljava/lang/String;)Landroid/os/flagging/AconfigPackage;
    .locals 0

    invoke-static {p0}, Landroid/os/flagging/AconfigPackage;->load(Ljava/lang/String;)Landroid/os/flagging/AconfigPackage;

    move-result-object p0

    return-object p0
.end method

.method public static bridge synthetic e()Ljava/lang/Class;
    .locals 1

    const-class v0, Landroid/app/Notification$ProgressStyle;

    return-object v0
.end method

.method public static bridge synthetic f(Landroid/os/flagging/AconfigPackage;Ljava/lang/String;Z)Z
    .locals 0

    invoke-virtual {p0, p1, p2}, Landroid/os/flagging/AconfigPackage;->getBooleanFlagValue(Ljava/lang/String;Z)Z

    move-result p0

    return p0
.end method

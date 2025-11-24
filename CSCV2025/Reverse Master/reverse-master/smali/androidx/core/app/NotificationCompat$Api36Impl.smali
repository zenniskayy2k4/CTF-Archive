.class Landroidx/core/app/NotificationCompat$Api36Impl;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation build Landroidx/annotation/RequiresApi;
    value = 0x24
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/core/app/NotificationCompat;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Api36Impl"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static hasPromotableCharacteristics(Landroid/app/Notification;)Z
    .locals 0

    invoke-virtual {p0}, Landroid/app/Notification;->hasPromotableCharacteristics()Z

    move-result p0

    return p0
.end method

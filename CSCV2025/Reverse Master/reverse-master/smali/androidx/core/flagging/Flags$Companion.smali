.class public final Landroidx/core/flagging/Flags$Companion;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/core/flagging/Flags;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lo/X0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/core/flagging/Flags$Companion;-><init>()V

    return-void
.end method

.method public static synthetic getBooleanFlagValue$default(Landroidx/core/flagging/Flags$Companion;Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z
    .locals 0

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    const/4 p3, 0x0

    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Landroidx/core/flagging/Flags$Companion;->getBooleanFlagValue(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result p0

    return p0
.end method


# virtual methods
.method public final getBooleanFlagValue(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 7

    .line 1
    const-string v0, "packageName"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "flagName"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x4

    const/4 v6, 0x0

    const/4 v4, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-static/range {v1 .. v6}, Landroidx/core/flagging/Flags$Companion;->getBooleanFlagValue$default(Landroidx/core/flagging/Flags$Companion;Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final getBooleanFlagValue(Ljava/lang/String;Ljava/lang/String;Z)Z
    .locals 4

    const-string v0, "packageName"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "flagName"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x24

    if-ge v0, v1, :cond_0

    return p3

    .line 3
    :cond_0
    invoke-static {}, Landroidx/core/flagging/Flags;->access$getAconfigCache$cp()Ljava/util/Map;

    move-result-object v0

    invoke-static {v0}, Lo/F2;->c(Ljava/lang/Object;)V

    .line 4
    invoke-static {}, Landroidx/core/flagging/Flags;->access$getMissingPackageCache$cp()Ljava/util/Set;

    move-result-object v1

    invoke-static {v1}, Lo/F2;->c(Ljava/lang/Object;)V

    .line 5
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    .line 6
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Lo/q;->c(Ljava/lang/Object;)Landroid/os/flagging/AconfigPackage;

    move-result-object p1

    goto :goto_1

    .line 7
    :cond_1
    invoke-interface {v1, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_2

    :goto_0
    move-object p1, v3

    goto :goto_1

    .line 8
    :cond_2
    :try_start_0
    invoke-static {p1}, Lo/q;->d(Ljava/lang/String;)Landroid/os/flagging/AconfigPackage;

    move-result-object v2

    .line 9
    invoke-interface {v0, p1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Landroid/os/flagging/AconfigStorageReadException; {:try_start_0 .. :try_end_0} :catch_0

    move-object p1, v2

    goto :goto_1

    .line 10
    :catch_0
    invoke-interface {v1, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :goto_1
    if-eqz p1, :cond_3

    .line 11
    invoke-static {p1, p2, p3}, Lo/q;->f(Landroid/os/flagging/AconfigPackage;Ljava/lang/String;Z)Z

    move-result p3

    :cond_3
    return p3
.end method

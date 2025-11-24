.class public final enum Lo/N0;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum a:Lo/N0;

.field public static final enum b:Lo/N0;

.field public static final enum c:Lo/N0;

.field public static final enum d:Lo/N0;

.field public static final enum e:Lo/N0;

.field public static final synthetic f:[Lo/N0;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Lo/N0;

    const-string v1, "CPU_ACQUIRED"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lo/N0;->a:Lo/N0;

    new-instance v1, Lo/N0;

    const-string v2, "BLOCKING"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v1, Lo/N0;->b:Lo/N0;

    new-instance v2, Lo/N0;

    const-string v3, "PARKING"

    const/4 v4, 0x2

    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v2, Lo/N0;->c:Lo/N0;

    new-instance v3, Lo/N0;

    const-string v4, "DORMANT"

    const/4 v5, 0x3

    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v3, Lo/N0;->d:Lo/N0;

    new-instance v4, Lo/N0;

    const-string v5, "TERMINATED"

    const/4 v6, 0x4

    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    sput-object v4, Lo/N0;->e:Lo/N0;

    filled-new-array {v0, v1, v2, v3, v4}, [Lo/N0;

    move-result-object v0

    sput-object v0, Lo/N0;->f:[Lo/N0;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lo/N0;
    .locals 1

    const-class v0, Lo/N0;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Lo/N0;

    return-object p0
.end method

.method public static values()[Lo/N0;
    .locals 1

    sget-object v0, Lo/N0;->f:[Lo/N0;

    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lo/N0;

    return-object v0
.end method

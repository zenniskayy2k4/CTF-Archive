.class public final Lo/p1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/H0;
.implements Ljava/io/Serializable;


# static fields
.field public static final a:Lo/p1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lo/p1;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Lo/p1;->a:Lo/p1;

    return-void
.end method


# virtual methods
.method public final fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;
    .locals 0

    return-object p1
.end method

.method public final get(Lo/G0;)Lo/F0;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public final hashCode()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final minusKey(Lo/G0;)Lo/H0;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public final plus(Lo/H0;)Lo/H0;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "EmptyCoroutineContext"

    return-object v0
.end method

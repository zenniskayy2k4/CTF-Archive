.class public final Lo/o5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/F0;
.implements Lo/G0;


# static fields
.field public static final a:Lo/o5;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lo/o5;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Lo/o5;->a:Lo/o5;

    return-void
.end method


# virtual methods
.method public final fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Lo/W1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final get(Lo/G0;)Lo/F0;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    return-object p0

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final getKey()Lo/G0;
    .locals 0

    return-object p0
.end method

.method public final minusKey(Lo/G0;)Lo/H0;
    .locals 0

    invoke-static {p0, p1}, Lo/F2;->n(Lo/F0;Lo/G0;)Lo/H0;

    move-result-object p1

    return-object p1
.end method

.method public final plus(Lo/H0;)Lo/H0;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Lo/W0;->g(Lo/H0;Lo/H0;)Lo/H0;

    move-result-object p1

    return-object p1
.end method

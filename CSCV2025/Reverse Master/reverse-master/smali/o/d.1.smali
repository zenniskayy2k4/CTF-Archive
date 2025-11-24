.class public abstract Lo/d;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/F0;


# instance fields
.field private final key:Lo/G0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/G0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lo/G0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/d;->key:Lo/G0;

    return-void
.end method


# virtual methods
.method public fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<R:",
            "Ljava/lang/Object;",
            ">(TR;",
            "Lo/W1;",
            ")TR;"
        }
    .end annotation

    const-string v0, "operation"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p2, p1, p0}, Lo/W1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public get(Lo/G0;)Lo/F0;
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Lo/F0;->getKey()Lo/G0;

    move-result-object v0

    invoke-static {v0, p1}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    return-object p0

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public getKey()Lo/G0;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lo/G0;"
        }
    .end annotation

    iget-object v0, p0, Lo/d;->key:Lo/G0;

    return-object v0
.end method

.method public minusKey(Lo/G0;)Lo/H0;
    .locals 0

    invoke-static {p0, p1}, Lo/F2;->n(Lo/F0;Lo/G0;)Lo/H0;

    move-result-object p1

    return-object p1
.end method

.method public plus(Lo/H0;)Lo/H0;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Lo/W0;->g(Lo/H0;Lo/H0;)Lo/H0;

    move-result-object p1

    return-object p1
.end method

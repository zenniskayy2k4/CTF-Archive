.class public abstract Lo/q4;
.super Lo/J;
.source "SourceFile"


# direct methods
.method public constructor <init>(Lo/B0;)V
    .locals 1

    invoke-direct {p0, p1}, Lo/J;-><init>(Lo/B0;)V

    if-eqz p1, :cond_1

    invoke-interface {p1}, Lo/B0;->getContext()Lo/H0;

    move-result-object p1

    sget-object v0, Lo/p1;->a:Lo/p1;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Coroutines with restricted suspension must have EmptyCoroutineContext"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    return-void
.end method


# virtual methods
.method public getContext()Lo/H0;
    .locals 1

    sget-object v0, Lo/p1;->a:Lo/p1;

    return-object v0
.end method

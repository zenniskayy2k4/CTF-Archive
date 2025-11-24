.class public final synthetic Lo/R2;
.super Lo/i2;
.source "SourceFile"

# interfaces
.implements Lo/S1;


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    iget-object v0, p0, Lo/P;->receiver:Ljava/lang/Object;

    check-cast v0, Lo/E2;

    invoke-interface {v0, p1}, Lo/E2;->c(Ljava/lang/Throwable;)V

    sget-object p1, Lo/p5;->a:Lo/p5;

    return-object p1
.end method

.class public abstract Lo/X4;
.super Lo/C0;
.source "SourceFile"

# interfaces
.implements Lo/g2;


# instance fields
.field private final arity:I


# direct methods
.method public constructor <init>(Lo/B0;)V
    .locals 0

    invoke-direct {p0, p1}, Lo/C0;-><init>(Lo/B0;)V

    const/4 p1, 0x2

    iput p1, p0, Lo/X4;->arity:I

    return-void
.end method


# virtual methods
.method public getArity()I
    .locals 1

    iget v0, p0, Lo/X4;->arity:I

    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Lo/J;->getCompletion()Lo/B0;

    move-result-object v0

    if-nez v0, :cond_0

    sget-object v0, Lo/l4;->a:Lo/m4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0}, Lo/m4;->a(Lo/g2;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "renderLambdaToString(...)"

    invoke-static {v0, v1}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_0
    invoke-super {p0}, Lo/J;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

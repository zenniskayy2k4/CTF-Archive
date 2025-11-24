.class public final Lo/b4;
.super Lo/C0;
.source "SourceFile"


# instance fields
.field public a:Lo/H1;

.field public synthetic b:Ljava/lang/Object;

.field public c:I


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iput-object p1, p0, Lo/b4;->b:Ljava/lang/Object;

    iget p1, p0, Lo/b4;->c:I

    const/high16 v0, -0x80000000

    or-int/2addr p1, v0

    iput p1, p0, Lo/b4;->c:I

    const/4 p1, 0x0

    invoke-static {p1, p0}, Lo/G4;->a(Landroidx/core/os/c;Lo/C0;)Ljava/lang/Object;

    sget-object p1, Lo/p5;->a:Lo/p5;

    return-object p1
.end method

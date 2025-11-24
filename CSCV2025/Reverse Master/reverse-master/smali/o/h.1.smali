.class public final Lo/h;
.super Lo/i;
.source "SourceFile"

# interfaces
.implements Ljava/util/RandomAccess;


# instance fields
.field public final a:Lo/i;

.field public final b:I

.field public final c:I


# direct methods
.method public constructor <init>(Lo/i;II)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/h;->a:Lo/i;

    iput p2, p0, Lo/h;->b:I

    sget-object v0, Lo/i;->Companion:Lo/e;

    invoke-virtual {p1}, Lo/b;->size()I

    move-result p1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p2, p3, p1}, Lo/e;->c(III)V

    sub-int/2addr p3, p2

    iput p3, p0, Lo/h;->c:I

    return-void
.end method


# virtual methods
.method public final get(I)Ljava/lang/Object;
    .locals 2

    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/h;->c:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->a(II)V

    iget v0, p0, Lo/h;->b:I

    add-int/2addr v0, p1

    iget-object p1, p0, Lo/h;->a:Lo/i;

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final getSize()I
    .locals 1

    iget v0, p0, Lo/h;->c:I

    return v0
.end method

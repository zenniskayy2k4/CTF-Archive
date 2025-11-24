.class public final Lo/B1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Iterator;
.implements Lo/c3;


# instance fields
.field public final a:Ljava/util/Iterator;

.field public b:I

.field public c:Ljava/lang/Object;

.field public final synthetic d:Lo/C1;


# direct methods
.method public constructor <init>(Lo/C1;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/B1;->d:Lo/C1;

    iget-object p1, p1, Lo/C1;->b:Ljava/lang/Object;

    check-cast p1, Lo/k2;

    new-instance v0, Lo/k5;

    invoke-direct {v0, p1}, Lo/k5;-><init>(Lo/k2;)V

    iput-object v0, p0, Lo/B1;->a:Ljava/util/Iterator;

    const/4 p1, -0x1

    iput p1, p0, Lo/B1;->b:I

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    :cond_0
    iget-object v0, p0, Lo/B1;->a:Ljava/util/Iterator;

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Lo/B1;->d:Lo/C1;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x1

    if-nez v0, :cond_1

    move v2, v1

    :cond_1
    if-nez v2, :cond_0

    iput-object v0, p0, Lo/B1;->c:Ljava/lang/Object;

    iput v1, p0, Lo/B1;->b:I

    return-void

    :cond_2
    iput v2, p0, Lo/B1;->b:I

    return-void
.end method

.method public final hasNext()Z
    .locals 2

    iget v0, p0, Lo/B1;->b:I

    const/4 v1, -0x1

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Lo/B1;->a()V

    :cond_0
    iget v0, p0, Lo/B1;->b:I

    const/4 v1, 0x1

    if-ne v0, v1, :cond_1

    return v1

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public final next()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Lo/B1;->b:I

    const/4 v1, -0x1

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Lo/B1;->a()V

    :cond_0
    iget v0, p0, Lo/B1;->b:I

    if-eqz v0, :cond_1

    iget-object v0, p0, Lo/B1;->c:Ljava/lang/Object;

    const/4 v2, 0x0

    iput-object v2, p0, Lo/B1;->c:Ljava/lang/Object;

    iput v1, p0, Lo/B1;->b:I

    return-object v0

    :cond_1
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    throw v0
.end method

.method public final remove()V
    .locals 2

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    const-string v1, "Operation is not supported for read-only collection"

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

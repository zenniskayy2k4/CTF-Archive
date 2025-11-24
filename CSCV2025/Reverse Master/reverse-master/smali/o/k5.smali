.class public final Lo/k5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Iterator;
.implements Lo/c3;


# instance fields
.field public final a:Ljava/util/Iterator;

.field public final synthetic b:Lo/k2;


# direct methods
.method public constructor <init>(Lo/k2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/k5;->b:Lo/k2;

    iget-object p1, p1, Lo/k2;->b:Ljava/lang/Object;

    check-cast p1, Lo/C4;

    invoke-interface {p1}, Lo/C4;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Lo/k5;->a:Ljava/util/Iterator;

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    iget-object v0, p0, Lo/k5;->a:Ljava/util/Iterator;

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    return v0
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Lo/k5;->b:Lo/k2;

    iget-object v0, v0, Lo/k2;->c:Ljava/lang/Object;

    check-cast v0, Lo/h3;

    iget-object v1, p0, Lo/k5;->a:Ljava/util/Iterator;

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v0, v1}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final remove()V
    .locals 2

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    const-string v1, "Operation is not supported for read-only collection"

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

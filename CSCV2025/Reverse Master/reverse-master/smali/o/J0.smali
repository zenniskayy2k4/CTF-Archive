.class public final Lo/J0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/G0;


# instance fields
.field public final a:Lo/h3;

.field public final b:Lo/G0;


# direct methods
.method public constructor <init>(Lo/G0;Lo/S1;)V
    .locals 1

    const-string v0, "baseKey"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p2, Lo/h3;

    iput-object p2, p0, Lo/J0;->a:Lo/h3;

    instance-of p2, p1, Lo/J0;

    if-eqz p2, :cond_0

    check-cast p1, Lo/J0;

    iget-object p1, p1, Lo/J0;->b:Lo/G0;

    :cond_0
    iput-object p1, p0, Lo/J0;->b:Lo/G0;

    return-void
.end method

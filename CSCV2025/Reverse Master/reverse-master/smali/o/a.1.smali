.class public final Lo/a;
.super Lo/h3;
.source "SourceFile"

# interfaces
.implements Lo/S1;


# instance fields
.field public final synthetic a:Lo/b;


# direct methods
.method public constructor <init>(Lo/b;)V
    .locals 0

    iput-object p1, p0, Lo/a;->a:Lo/b;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Lo/h3;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Lo/a;->a:Lo/b;

    if-ne p1, v0, :cond_0

    const-string p1, "(this Collection)"

    return-object p1

    :cond_0
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

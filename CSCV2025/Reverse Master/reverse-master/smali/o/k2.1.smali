.class public final Lo/k2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/C4;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lo/C4;Lo/S1;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lo/k2;->a:I

    const-string v0, "transformer"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lo/k2;->b:Ljava/lang/Object;

    check-cast p2, Lo/h3;

    iput-object p2, p0, Lo/k2;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lo/H4;Lo/S1;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lo/k2;->a:I

    const-string v0, "getNextValue"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/k2;->b:Ljava/lang/Object;

    iput-object p2, p0, Lo/k2;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    iget v0, p0, Lo/k2;->a:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Lo/k5;

    invoke-direct {v0, p0}, Lo/k5;-><init>(Lo/k2;)V

    return-object v0

    :pswitch_0
    new-instance v0, Lo/j2;

    invoke-direct {v0, p0}, Lo/j2;-><init>(Lo/k2;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

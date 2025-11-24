.class public final Lo/C1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/C4;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;)V
    .locals 0

    iput p1, p0, Lo/C1;->a:I

    iput-object p2, p0, Lo/C1;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    iget v0, p0, Lo/C1;->a:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Lo/C1;->b:Ljava/lang/Object;

    check-cast v0, Ljava/util/Iterator;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Lo/C1;->b:Ljava/lang/Object;

    check-cast v0, Lo/W1;

    invoke-static {v0}, Lo/G4;->f(Lo/W1;)Lo/D4;

    move-result-object v0

    return-object v0

    :pswitch_1
    new-instance v0, Lo/B1;

    invoke-direct {v0, p0}, Lo/B1;-><init>(Lo/C1;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

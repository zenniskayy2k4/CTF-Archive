.class public final synthetic Lo/y;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/S1;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Lo/y;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Lo/y;->a:I

    check-cast p1, Landroid/animation/Animator;

    packed-switch v0, :pswitch_data_0

    invoke-static {p1}, Landroidx/core/animation/AnimatorKt;->a(Landroid/animation/Animator;)Lo/p5;

    move-result-object p1

    return-object p1

    :pswitch_0
    invoke-static {p1}, Landroidx/core/animation/AnimatorKt;->b(Landroid/animation/Animator;)Lo/p5;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public final synthetic Lo/g4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/animation/ValueAnimator$AnimatorUpdateListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Landroidx/core/view/insets/Protection;


# direct methods
.method public synthetic constructor <init>(Landroidx/core/view/insets/Protection;I)V
    .locals 0

    iput p2, p0, Lo/g4;->a:I

    iput-object p1, p0, Lo/g4;->b:Landroidx/core/view/insets/Protection;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onAnimationUpdate(Landroid/animation/ValueAnimator;)V
    .locals 1

    iget v0, p0, Lo/g4;->a:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Lo/g4;->b:Landroidx/core/view/insets/Protection;

    invoke-static {v0, p1}, Landroidx/core/view/insets/Protection;->a(Landroidx/core/view/insets/Protection;Landroid/animation/ValueAnimator;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Lo/g4;->b:Landroidx/core/view/insets/Protection;

    invoke-static {v0, p1}, Landroidx/core/view/insets/Protection;->b(Landroidx/core/view/insets/Protection;Landroid/animation/ValueAnimator;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

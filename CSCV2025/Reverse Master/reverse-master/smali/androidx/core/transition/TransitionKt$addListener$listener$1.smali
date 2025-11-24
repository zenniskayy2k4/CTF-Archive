.class public final Landroidx/core/transition/TransitionKt$addListener$listener$1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/transition/Transition$TransitionListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/core/transition/TransitionKt;->addListener(Landroid/transition/Transition;Lo/S1;Lo/S1;Lo/S1;Lo/S1;Lo/S1;)Landroid/transition/Transition$TransitionListener;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field final synthetic $onCancel:Lo/S1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/S1;"
        }
    .end annotation
.end field

.field final synthetic $onEnd:Lo/S1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/S1;"
        }
    .end annotation
.end field

.field final synthetic $onPause:Lo/S1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/S1;"
        }
    .end annotation
.end field

.field final synthetic $onResume:Lo/S1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/S1;"
        }
    .end annotation
.end field

.field final synthetic $onStart:Lo/S1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/S1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lo/S1;Lo/S1;Lo/S1;Lo/S1;Lo/S1;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lo/S1;",
            "Lo/S1;",
            "Lo/S1;",
            "Lo/S1;",
            "Lo/S1;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onEnd:Lo/S1;

    iput-object p2, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onResume:Lo/S1;

    iput-object p3, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onPause:Lo/S1;

    iput-object p4, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onCancel:Lo/S1;

    iput-object p5, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onStart:Lo/S1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onTransitionCancel(Landroid/transition/Transition;)V
    .locals 1

    iget-object v0, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onCancel:Lo/S1;

    invoke-interface {v0, p1}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public onTransitionEnd(Landroid/transition/Transition;)V
    .locals 1

    iget-object v0, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onEnd:Lo/S1;

    invoke-interface {v0, p1}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public onTransitionPause(Landroid/transition/Transition;)V
    .locals 1

    iget-object v0, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onPause:Lo/S1;

    invoke-interface {v0, p1}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public onTransitionResume(Landroid/transition/Transition;)V
    .locals 1

    iget-object v0, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onResume:Lo/S1;

    invoke-interface {v0, p1}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public onTransitionStart(Landroid/transition/Transition;)V
    .locals 1

    iget-object v0, p0, Landroidx/core/transition/TransitionKt$addListener$listener$1;->$onStart:Lo/S1;

    invoke-interface {v0, p1}, Lo/S1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.class public final Landroidx/core/animation/AnimatorKt$addListener$1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/S1;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/core/animation/AnimatorKt;->addListener$default(Landroid/animation/Animator;Lo/S1;Lo/S1;Lo/S1;Lo/S1;ILjava/lang/Object;)Landroid/animation/Animator$AnimatorListener;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lo/S1;"
    }
.end annotation


# static fields
.field public static final INSTANCE:Landroidx/core/animation/AnimatorKt$addListener$1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/core/animation/AnimatorKt$addListener$1;

    invoke-direct {v0}, Landroidx/core/animation/AnimatorKt$addListener$1;-><init>()V

    sput-object v0, Landroidx/core/animation/AnimatorKt$addListener$1;->INSTANCE:Landroidx/core/animation/AnimatorKt$addListener$1;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 2
    check-cast p1, Landroid/animation/Animator;

    invoke-virtual {p0, p1}, Landroidx/core/animation/AnimatorKt$addListener$1;->invoke(Landroid/animation/Animator;)V

    sget-object p1, Lo/p5;->a:Lo/p5;

    return-object p1
.end method

.method public final invoke(Landroid/animation/Animator;)V
    .locals 0

    .line 1
    return-void
.end method

.class public final synthetic Lo/z;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/animation/ValueAnimator$AnimatorUpdateListener;


# instance fields
.field public final synthetic a:Lcom/google/android/material/appbar/AppBarLayout;

.field public final synthetic b:Landroid/content/res/ColorStateList;

.field public final synthetic c:Lcom/google/android/material/shape/MaterialShapeDrawable;

.field public final synthetic d:Ljava/lang/Integer;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/appbar/AppBarLayout;Landroid/content/res/ColorStateList;Lcom/google/android/material/shape/MaterialShapeDrawable;Ljava/lang/Integer;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/z;->a:Lcom/google/android/material/appbar/AppBarLayout;

    iput-object p2, p0, Lo/z;->b:Landroid/content/res/ColorStateList;

    iput-object p3, p0, Lo/z;->c:Lcom/google/android/material/shape/MaterialShapeDrawable;

    iput-object p4, p0, Lo/z;->d:Ljava/lang/Integer;

    return-void
.end method


# virtual methods
.method public final onAnimationUpdate(Landroid/animation/ValueAnimator;)V
    .locals 4

    iget-object v0, p0, Lo/z;->a:Lcom/google/android/material/appbar/AppBarLayout;

    iget-object v1, p0, Lo/z;->b:Landroid/content/res/ColorStateList;

    iget-object v2, p0, Lo/z;->c:Lcom/google/android/material/shape/MaterialShapeDrawable;

    iget-object v3, p0, Lo/z;->d:Ljava/lang/Integer;

    invoke-static {v0, v1, v2, v3, p1}, Lcom/google/android/material/appbar/AppBarLayout;->b(Lcom/google/android/material/appbar/AppBarLayout;Landroid/content/res/ColorStateList;Lcom/google/android/material/shape/MaterialShapeDrawable;Ljava/lang/Integer;Landroid/animation/ValueAnimator;)V

    return-void
.end method

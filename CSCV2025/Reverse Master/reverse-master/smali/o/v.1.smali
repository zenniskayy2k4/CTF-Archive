.class public final synthetic Lo/v;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/graphics/shapes/FindMinimumFunction;


# instance fields
.field public final synthetic a:Landroidx/graphics/shapes/Cubic;

.field public final synthetic b:Landroidx/graphics/shapes/AngleMeasurer;

.field public final synthetic c:F

.field public final synthetic d:F


# direct methods
.method public synthetic constructor <init>(Landroidx/graphics/shapes/Cubic;Landroidx/graphics/shapes/AngleMeasurer;FF)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/v;->a:Landroidx/graphics/shapes/Cubic;

    iput-object p2, p0, Lo/v;->b:Landroidx/graphics/shapes/AngleMeasurer;

    iput p3, p0, Lo/v;->c:F

    iput p4, p0, Lo/v;->d:F

    return-void
.end method


# virtual methods
.method public final invoke(F)F
    .locals 4

    iget-object v0, p0, Lo/v;->a:Landroidx/graphics/shapes/Cubic;

    iget-object v1, p0, Lo/v;->b:Landroidx/graphics/shapes/AngleMeasurer;

    iget v2, p0, Lo/v;->c:F

    iget v3, p0, Lo/v;->d:F

    invoke-static {v0, v1, v2, v3, p1}, Landroidx/graphics/shapes/AngleMeasurer;->a(Landroidx/graphics/shapes/Cubic;Landroidx/graphics/shapes/AngleMeasurer;FFF)F

    move-result p1

    return p1
.end method

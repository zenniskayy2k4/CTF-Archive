.class public final Lcom/google/android/material/color/utilities/ViewingConditions;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation build Landroidx/annotation/RestrictTo;
    value = {
        .enum Landroidx/annotation/RestrictTo$Scope;->LIBRARY_GROUP:Landroidx/annotation/RestrictTo$Scope;
    }
.end annotation


# static fields
.field public static final DEFAULT:Lcom/google/android/material/color/utilities/ViewingConditions;


# instance fields
.field private final aw:D

.field private final c:D

.field private final fl:D

.field private final flRoot:D

.field private final n:D

.field private final nbb:D

.field private final nc:D

.field private final ncb:D

.field private final rgbD:[D

.field private final z:D


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-wide/high16 v0, 0x4049000000000000L    # 50.0

    invoke-static {v0, v1}, Lcom/google/android/material/color/utilities/ViewingConditions;->defaultWithBackgroundLstar(D)Lcom/google/android/material/color/utilities/ViewingConditions;

    move-result-object v0

    sput-object v0, Lcom/google/android/material/color/utilities/ViewingConditions;->DEFAULT:Lcom/google/android/material/color/utilities/ViewingConditions;

    return-void
.end method

.method private constructor <init>(DDDDDD[DDDD)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->n:D

    iput-wide p3, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->aw:D

    iput-wide p5, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->nbb:D

    iput-wide p7, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->ncb:D

    iput-wide p9, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->c:D

    iput-wide p11, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->nc:D

    iput-object p13, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->rgbD:[D

    iput-wide p14, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->fl:D

    move-wide/from16 p1, p16

    iput-wide p1, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->flRoot:D

    move-wide/from16 p1, p18

    iput-wide p1, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->z:D

    return-void
.end method

.method public static defaultWithBackgroundLstar(D)Lcom/google/android/material/color/utilities/ViewingConditions;
    .locals 8

    invoke-static {}, Lcom/google/android/material/color/utilities/ColorUtils;->whitePointD65()[D

    move-result-object v0

    const-wide/high16 v1, 0x4049000000000000L    # 50.0

    invoke-static {v1, v2}, Lcom/google/android/material/color/utilities/ColorUtils;->yFromLstar(D)D

    move-result-wide v1

    const-wide v3, 0x404fd4bbab8b494cL    # 63.66197723675813

    mul-double/2addr v1, v3

    const-wide/high16 v3, 0x4059000000000000L    # 100.0

    div-double/2addr v1, v3

    const-wide/high16 v5, 0x4000000000000000L    # 2.0

    const/4 v7, 0x0

    move-wide v3, p0

    invoke-static/range {v0 .. v7}, Lcom/google/android/material/color/utilities/ViewingConditions;->make([DDDDZ)Lcom/google/android/material/color/utilities/ViewingConditions;

    move-result-object p0

    return-object p0
.end method

.method public static make([DDDDZ)Lcom/google/android/material/color/utilities/ViewingConditions;
    .locals 45

    move-wide/from16 v0, p1

    const/4 v2, 0x3

    const-wide v3, 0x3fb999999999999aL    # 0.1

    move-wide/from16 v5, p3

    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->max(DD)D

    move-result-wide v5

    sget-object v7, Lcom/google/android/material/color/utilities/Cam16;->XYZ_TO_CAM16RGB:[[D

    const/4 v8, 0x0

    aget-wide v9, p0, v8

    aget-object v11, v7, v8

    aget-wide v12, v11, v8

    mul-double/2addr v12, v9

    const/4 v14, 0x1

    aget-wide v15, p0, v14

    aget-wide v17, v11, v14

    mul-double v17, v17, v15

    add-double v17, v17, v12

    const/4 v12, 0x2

    aget-wide v19, p0, v12

    aget-wide v21, v11, v12

    mul-double v21, v21, v19

    add-double v21, v21, v17

    aget-object v11, v7, v14

    aget-wide v17, v11, v8

    mul-double v17, v17, v9

    aget-wide v23, v11, v14

    mul-double v23, v23, v15

    add-double v23, v23, v17

    aget-wide v17, v11, v12

    mul-double v17, v17, v19

    add-double v17, v17, v23

    aget-object v7, v7, v12

    aget-wide v23, v7, v8

    mul-double v9, v9, v23

    aget-wide v23, v7, v14

    mul-double v15, v15, v23

    add-double/2addr v15, v9

    aget-wide v9, v7, v12

    mul-double v19, v19, v9

    add-double v19, v19, v15

    const-wide/high16 v9, 0x4024000000000000L    # 10.0

    div-double v15, p5, v9

    const-wide v23, 0x3fe999999999999aL    # 0.8

    add-double v36, v15, v23

    const-wide v15, 0x3feccccccccccccdL    # 0.9

    cmpl-double v7, v36, v15

    if-ltz v7, :cond_0

    sub-double v15, v36, v15

    mul-double v27, v15, v9

    const-wide v23, 0x3fe2e147ae147ae1L    # 0.59

    const-wide v25, 0x3fe6147ae147ae14L    # 0.69

    invoke-static/range {v23 .. v28}, Lcom/google/android/material/color/utilities/MathUtils;->lerp(DDD)D

    move-result-wide v9

    :goto_0
    move-wide/from16 v34, v9

    goto :goto_1

    :cond_0
    sub-double v15, v36, v23

    mul-double v27, v15, v9

    const-wide v23, 0x3fe0cccccccccccdL    # 0.525

    const-wide v25, 0x3fe2e147ae147ae1L    # 0.59

    invoke-static/range {v23 .. v28}, Lcom/google/android/material/color/utilities/MathUtils;->lerp(DDD)D

    move-result-wide v9

    goto :goto_0

    :goto_1
    const-wide/high16 v9, 0x3ff0000000000000L    # 1.0

    if-eqz p7, :cond_1

    move-wide v15, v3

    move-wide/from16 v27, v9

    goto :goto_2

    :cond_1
    move-wide v15, v3

    neg-double v3, v0

    const-wide/high16 v23, 0x4045000000000000L    # 42.0

    sub-double v3, v3, v23

    const-wide/high16 v23, 0x4057000000000000L    # 92.0

    div-double v3, v3, v23

    invoke-static {v3, v4}, Ljava/lang/Math;->exp(D)D

    move-result-wide v3

    const-wide v23, 0x3fd1c71c71c71c72L    # 0.2777777777777778

    mul-double v3, v3, v23

    sub-double v3, v9, v3

    mul-double v3, v3, v36

    move-wide/from16 v27, v3

    :goto_2
    const-wide/16 v23, 0x0

    const-wide/high16 v25, 0x3ff0000000000000L    # 1.0

    invoke-static/range {v23 .. v28}, Lcom/google/android/material/color/utilities/MathUtils;->clampDouble(DDD)D

    move-result-wide v3

    const-wide/high16 v23, 0x4059000000000000L    # 100.0

    div-double v25, v23, v21

    mul-double v25, v25, v3

    add-double v25, v25, v9

    sub-double v25, v25, v3

    div-double v27, v23, v17

    mul-double v27, v27, v3

    add-double v27, v27, v9

    sub-double v27, v27, v3

    div-double v29, v23, v19

    mul-double v29, v29, v3

    add-double v29, v29, v9

    sub-double v29, v29, v3

    new-array v3, v2, [D

    aput-wide v25, v3, v8

    aput-wide v27, v3, v14

    aput-wide v29, v3, v12

    const-wide/high16 v25, 0x4014000000000000L    # 5.0

    mul-double v25, v25, v0

    add-double v27, v25, v9

    div-double v27, v9, v27

    mul-double v29, v27, v27

    mul-double v29, v29, v27

    mul-double v29, v29, v27

    sub-double v9, v9, v29

    mul-double v29, v29, v0

    mul-double v0, v9, v15

    mul-double/2addr v0, v9

    invoke-static/range {v25 .. v26}, Ljava/lang/Math;->cbrt(D)D

    move-result-wide v9

    mul-double/2addr v9, v0

    add-double v9, v9, v29

    invoke-static {v5, v6}, Lcom/google/android/material/color/utilities/ColorUtils;->yFromLstar(D)D

    move-result-wide v0

    aget-wide v4, p0, v14

    div-double/2addr v0, v4

    const-wide v4, 0x3ff7ae147ae147aeL    # 1.48

    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v6

    add-double v43, v6, v4

    const-wide v4, 0x3fc999999999999aL    # 0.2

    invoke-static {v0, v1, v4, v5}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v4

    const-wide v6, 0x3fe7333333333333L    # 0.725

    div-double v30, v6, v4

    aget-wide v4, v3, v8

    mul-double/2addr v4, v9

    mul-double v4, v4, v21

    div-double v4, v4, v23

    const-wide v6, 0x3fdae147ae147ae1L    # 0.42

    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v4

    aget-wide v15, v3, v14

    mul-double/2addr v15, v9

    mul-double v15, v15, v17

    move/from16 p3, v12

    div-double v12, v15, v23

    invoke-static {v12, v13, v6, v7}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v11

    aget-wide v15, v3, p3

    mul-double/2addr v15, v9

    mul-double v15, v15, v19

    move/from16 p4, v14

    div-double v14, v15, v23

    invoke-static {v14, v15, v6, v7}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v6

    new-array v13, v2, [D

    aput-wide v4, v13, v8

    aput-wide v11, v13, p4

    aput-wide v6, v13, p3

    aget-wide v4, v13, v8

    const-wide/high16 v6, 0x4079000000000000L    # 400.0

    mul-double v11, v4, v6

    const-wide v14, 0x403b2147ae147ae1L    # 27.13

    add-double/2addr v4, v14

    div-double/2addr v11, v4

    aget-wide v4, v13, p4

    mul-double v16, v4, v6

    add-double/2addr v4, v14

    div-double v16, v16, v4

    aget-wide v4, v13, p3

    mul-double/2addr v6, v4

    add-double/2addr v4, v14

    div-double/2addr v6, v4

    new-array v2, v2, [D

    aput-wide v11, v2, v8

    aput-wide v16, v2, p4

    aput-wide v6, v2, p3

    const-wide/high16 v4, 0x4000000000000000L    # 2.0

    aget-wide v6, v2, v8

    mul-double/2addr v6, v4

    aget-wide v4, v2, p4

    add-double/2addr v6, v4

    const-wide v4, 0x3fa999999999999aL    # 0.05

    aget-wide v11, v2, p3

    mul-double/2addr v11, v4

    add-double/2addr v11, v6

    mul-double v28, v11, v30

    new-instance v25, Lcom/google/android/material/color/utilities/ViewingConditions;

    const-wide/high16 v4, 0x3fd0000000000000L    # 0.25

    invoke-static {v9, v10, v4, v5}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v41

    move-wide/from16 v32, v30

    move-wide/from16 v26, v0

    move-object/from16 v38, v3

    move-wide/from16 v39, v9

    invoke-direct/range {v25 .. v44}, Lcom/google/android/material/color/utilities/ViewingConditions;-><init>(DDDDDD[DDDD)V

    return-object v25
.end method


# virtual methods
.method public getAw()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->aw:D

    return-wide v0
.end method

.method public getC()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->c:D

    return-wide v0
.end method

.method public getFl()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->fl:D

    return-wide v0
.end method

.method public getFlRoot()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->flRoot:D

    return-wide v0
.end method

.method public getN()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->n:D

    return-wide v0
.end method

.method public getNbb()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->nbb:D

    return-wide v0
.end method

.method public getNc()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->nc:D

    return-wide v0
.end method

.method public getNcb()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->ncb:D

    return-wide v0
.end method

.method public getRgbD()[D
    .locals 1

    iget-object v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->rgbD:[D

    return-object v0
.end method

.method public getZ()D
    .locals 2

    iget-wide v0, p0, Lcom/google/android/material/color/utilities/ViewingConditions;->z:D

    return-wide v0
.end method

.class public Lcom/google/android/material/color/utilities/DynamicScheme;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation build Landroidx/annotation/RestrictTo;
    value = {
        .enum Landroidx/annotation/RestrictTo$Scope;->LIBRARY_GROUP:Landroidx/annotation/RestrictTo$Scope;
    }
.end annotation


# instance fields
.field public final contrastLevel:D

.field public final errorPalette:Lcom/google/android/material/color/utilities/TonalPalette;

.field public final isDark:Z

.field public final neutralPalette:Lcom/google/android/material/color/utilities/TonalPalette;

.field public final neutralVariantPalette:Lcom/google/android/material/color/utilities/TonalPalette;

.field public final primaryPalette:Lcom/google/android/material/color/utilities/TonalPalette;

.field public final secondaryPalette:Lcom/google/android/material/color/utilities/TonalPalette;

.field public final sourceColorArgb:I

.field public final sourceColorHct:Lcom/google/android/material/color/utilities/Hct;

.field public final tertiaryPalette:Lcom/google/android/material/color/utilities/TonalPalette;

.field public final variant:Lcom/google/android/material/color/utilities/Variant;


# direct methods
.method public constructor <init>(Lcom/google/android/material/color/utilities/Hct;Lcom/google/android/material/color/utilities/Variant;ZDLcom/google/android/material/color/utilities/TonalPalette;Lcom/google/android/material/color/utilities/TonalPalette;Lcom/google/android/material/color/utilities/TonalPalette;Lcom/google/android/material/color/utilities/TonalPalette;Lcom/google/android/material/color/utilities/TonalPalette;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1}, Lcom/google/android/material/color/utilities/Hct;->toInt()I

    move-result v0

    iput v0, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->sourceColorArgb:I

    iput-object p1, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->sourceColorHct:Lcom/google/android/material/color/utilities/Hct;

    iput-object p2, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->variant:Lcom/google/android/material/color/utilities/Variant;

    iput-boolean p3, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->isDark:Z

    iput-wide p4, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->contrastLevel:D

    iput-object p6, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->primaryPalette:Lcom/google/android/material/color/utilities/TonalPalette;

    iput-object p7, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->secondaryPalette:Lcom/google/android/material/color/utilities/TonalPalette;

    iput-object p8, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->tertiaryPalette:Lcom/google/android/material/color/utilities/TonalPalette;

    iput-object p9, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->neutralPalette:Lcom/google/android/material/color/utilities/TonalPalette;

    iput-object p10, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->neutralVariantPalette:Lcom/google/android/material/color/utilities/TonalPalette;

    const-wide/high16 p1, 0x4039000000000000L    # 25.0

    const-wide/high16 p3, 0x4055000000000000L    # 84.0

    invoke-static {p1, p2, p3, p4}, Lcom/google/android/material/color/utilities/TonalPalette;->fromHueAndChroma(DD)Lcom/google/android/material/color/utilities/TonalPalette;

    move-result-object p1

    iput-object p1, p0, Lcom/google/android/material/color/utilities/DynamicScheme;->errorPalette:Lcom/google/android/material/color/utilities/TonalPalette;

    return-void
.end method

.method public static getRotatedHue(Lcom/google/android/material/color/utilities/Hct;[D[D)D
    .locals 8

    invoke-virtual {p0}, Lcom/google/android/material/color/utilities/Hct;->getHue()D

    move-result-wide v0

    array-length p0, p2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-ne p0, v2, :cond_0

    aget-wide p0, p2, v3

    add-double/2addr v0, p0

    invoke-static {v0, v1}, Lcom/google/android/material/color/utilities/MathUtils;->sanitizeDegreesDouble(D)D

    move-result-wide p0

    return-wide p0

    :cond_0
    array-length p0, p1

    :goto_0
    add-int/lit8 v2, p0, -0x2

    if-gt v3, v2, :cond_2

    aget-wide v4, p1, v3

    add-int/lit8 v2, v3, 0x1

    aget-wide v6, p1, v2

    cmpg-double v4, v4, v0

    if-gez v4, :cond_1

    cmpg-double v4, v0, v6

    if-gez v4, :cond_1

    aget-wide p0, p2, v3

    add-double/2addr v0, p0

    invoke-static {v0, v1}, Lcom/google/android/material/color/utilities/MathUtils;->sanitizeDegreesDouble(D)D

    move-result-wide p0

    return-wide p0

    :cond_1
    move v3, v2

    goto :goto_0

    :cond_2
    return-wide v0
.end method


# virtual methods
.method public getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I
    .locals 0
    .param p1    # Lcom/google/android/material/color/utilities/DynamicColor;
        .annotation build Landroidx/annotation/NonNull;
        .end annotation
    .end param

    invoke-virtual {p1, p0}, Lcom/google/android/material/color/utilities/DynamicColor;->getArgb(Lcom/google/android/material/color/utilities/DynamicScheme;)I

    move-result p1

    return p1
.end method

.method public getBackground()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->background()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getControlActivated()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->controlActivated()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getControlHighlight()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->controlHighlight()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getControlNormal()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->controlNormal()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getError()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->error()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getErrorContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->errorContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getHct(Lcom/google/android/material/color/utilities/DynamicColor;)Lcom/google/android/material/color/utilities/Hct;
    .locals 0
    .param p1    # Lcom/google/android/material/color/utilities/DynamicColor;
        .annotation build Landroidx/annotation/NonNull;
        .end annotation
    .end param
    .annotation build Landroidx/annotation/NonNull;
    .end annotation

    invoke-virtual {p1, p0}, Lcom/google/android/material/color/utilities/DynamicColor;->getHct(Lcom/google/android/material/color/utilities/DynamicScheme;)Lcom/google/android/material/color/utilities/Hct;

    move-result-object p1

    return-object p1
.end method

.method public getInverseOnSurface()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->inverseOnSurface()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getInversePrimary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->inversePrimary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getInverseSurface()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->inverseSurface()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getNeutralPaletteKeyColor()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->neutralPaletteKeyColor()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getNeutralVariantPaletteKeyColor()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->neutralVariantPaletteKeyColor()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnBackground()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onBackground()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnError()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onError()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnErrorContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onErrorContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnPrimary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onPrimary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnPrimaryContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onPrimaryContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnPrimaryFixed()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onPrimaryFixed()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnPrimaryFixedVariant()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onPrimaryFixedVariant()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnSecondary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onSecondary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnSecondaryContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onSecondaryContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnSecondaryFixed()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onSecondaryFixed()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnSecondaryFixedVariant()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onSecondaryFixedVariant()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnSurface()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onSurface()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnSurfaceVariant()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onSurfaceVariant()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnTertiary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onTertiary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnTertiaryContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onTertiaryContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnTertiaryFixed()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onTertiaryFixed()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOnTertiaryFixedVariant()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->onTertiaryFixedVariant()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOutline()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->outline()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getOutlineVariant()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->outlineVariant()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getPrimary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->primary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getPrimaryContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->primaryContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getPrimaryFixed()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->primaryFixed()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getPrimaryFixedDim()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->primaryFixedDim()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getPrimaryPaletteKeyColor()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->primaryPaletteKeyColor()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getScrim()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->scrim()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSecondary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->secondary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSecondaryContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->secondaryContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSecondaryFixed()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->secondaryFixed()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSecondaryFixedDim()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->secondaryFixedDim()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSecondaryPaletteKeyColor()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->secondaryPaletteKeyColor()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getShadow()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->shadow()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurface()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surface()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceBright()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceBright()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceContainerHigh()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceContainerHigh()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceContainerHighest()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceContainerHighest()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceContainerLow()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceContainerLow()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceContainerLowest()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceContainerLowest()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceDim()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceDim()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceTint()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceTint()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getSurfaceVariant()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->surfaceVariant()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTertiary()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->tertiary()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTertiaryContainer()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->tertiaryContainer()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTertiaryFixed()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->tertiaryFixed()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTertiaryFixedDim()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->tertiaryFixedDim()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTertiaryPaletteKeyColor()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->tertiaryPaletteKeyColor()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTextHintInverse()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->textHintInverse()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTextPrimaryInverse()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->textPrimaryInverse()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTextPrimaryInverseDisableOnly()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->textPrimaryInverseDisableOnly()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTextSecondaryAndTertiaryInverse()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->textSecondaryAndTertiaryInverse()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

.method public getTextSecondaryAndTertiaryInverseDisabled()I
    .locals 1

    new-instance v0, Lcom/google/android/material/color/utilities/MaterialDynamicColors;

    invoke-direct {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;-><init>()V

    invoke-virtual {v0}, Lcom/google/android/material/color/utilities/MaterialDynamicColors;->textSecondaryAndTertiaryInverseDisabled()Lcom/google/android/material/color/utilities/DynamicColor;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/google/android/material/color/utilities/DynamicScheme;->getArgb(Lcom/google/android/material/color/utilities/DynamicColor;)I

    move-result v0

    return v0
.end method

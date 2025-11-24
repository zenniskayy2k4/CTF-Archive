.class public Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final DURATION_OF_CHILD_MEASURES:I = 0x5

.field public static final DURATION_OF_LAYOUT:I = 0x7

.field public static final DURATION_OF_MEASURES:I = 0x6

.field private static MAX_WORD:I = 0x19

.field public static final NUMBER_OF_CHILD_MEASURES:I = 0x4

.field public static final NUMBER_OF_CHILD_VIEWS:I = 0x3

.field public static final NUMBER_OF_EQUATIONS:I = 0x9

.field public static final NUMBER_OF_LAYOUTS:I = 0x1

.field public static final NUMBER_OF_ON_MEASURES:I = 0x2

.field public static final NUMBER_OF_SIMPLE_EQUATIONS:I = 0xa

.field public static final NUMBER_OF_VARIABLES:I = 0x8

.field private static final WORD_PAD:Ljava/lang/String;


# instance fields
.field mConstraintLayout:Landroidx/constraintlayout/widget/ConstraintLayout;

.field private final mMetrics:Landroidx/constraintlayout/core/Metrics;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Ljava/lang/String;

    const/16 v1, 0x19

    new-array v1, v1, [C

    invoke-direct {v0, v1}, Ljava/lang/String;-><init>([C)V

    const/4 v1, 0x0

    const/16 v2, 0x20

    invoke-virtual {v0, v1, v2}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->WORD_PAD:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroidx/constraintlayout/widget/ConstraintLayout;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Landroidx/constraintlayout/core/Metrics;

    invoke-direct {v0}, Landroidx/constraintlayout/core/Metrics;-><init>()V

    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    .line 3
    invoke-virtual {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->attach(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    return-void
.end method

.method public constructor <init>(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;)V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    new-instance v0, Landroidx/constraintlayout/core/Metrics;

    invoke-direct {v0}, Landroidx/constraintlayout/core/Metrics;-><init>()V

    iput-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    .line 6
    iget-object p1, p1, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    invoke-virtual {v0, p1}, Landroidx/constraintlayout/core/Metrics;->copy(Landroidx/constraintlayout/core/Metrics;)V

    return-void
.end method

.method private compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;
    .locals 3

    .line 34
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->getValue(I)J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v1, " -> "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->getValue(I)J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    .line 35
    invoke-virtual {p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->geName(I)Ljava/lang/String;

    move-result-object p2

    .line 36
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->WORD_PAD:Ljava/lang/String;

    .line 37
    invoke-static {v0, v1, p2}, Lo/l;->i(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 38
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    sget v1, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->MAX_WORD:I

    sub-int/2addr v0, v1

    invoke-virtual {p2, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p2

    .line 39
    const-string v0, " = "

    .line 40
    invoke-static {p2, v0}, Lo/l;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 41
    const-string v0, "CL Perf: "

    .line 42
    invoke-static {v0, p2, p1}, Lo/l;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method private compare(Ljava/text/DecimalFormat;Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;
    .locals 5

    .line 1
    invoke-virtual {p0, p3}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->getValue(I)J

    move-result-wide v0

    long-to-float v0, v0

    const v1, 0x358637bd    # 1.0E-6f

    mul-float/2addr v0, v1

    const/4 v2, 0x7

    invoke-direct {p0, p1, v0, v2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->fmt(Ljava/text/DecimalFormat;FI)Ljava/lang/String;

    move-result-object v0

    .line 2
    const-string v3, " -> "

    .line 3
    invoke-static {v0, v3}, Lo/l;->o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    .line 4
    invoke-virtual {p2, p3}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->getValue(I)J

    move-result-wide v3

    long-to-float p2, v3

    mul-float/2addr p2, v1

    invoke-direct {p0, p1, p2, v2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->fmt(Ljava/text/DecimalFormat;FI)Ljava/lang/String;

    move-result-object p1

    const-string p2, "ms"

    .line 5
    invoke-static {v0, p1, p2}, Lo/l;->i(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 6
    invoke-virtual {p0, p3}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->geName(I)Ljava/lang/String;

    move-result-object p2

    .line 7
    new-instance p3, Ljava/lang/StringBuilder;

    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->WORD_PAD:Ljava/lang/String;

    .line 8
    invoke-static {p3, v0, p2}, Lo/l;->i(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 9
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result p3

    sget v0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->MAX_WORD:I

    sub-int/2addr p3, v0

    invoke-virtual {p2, p3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p2

    .line 10
    const-string p3, " = "

    .line 11
    invoke-static {p2, p3}, Lo/l;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 12
    const-string p3, "CL Perf: "

    .line 13
    invoke-static {p3, p2, p1}, Lo/l;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method private fmt(Ljava/text/DecimalFormat;FI)Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/String;

    new-array v1, p3, [C

    invoke-direct {v0, v1}, Ljava/lang/String;-><init>([C)V

    const/4 v1, 0x0

    const/16 v2, 0x20

    invoke-virtual {v0, v1, v2}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lo/l;->m(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    float-to-double v1, p2

    invoke-virtual {p1, v1, v2}, Ljava/text/NumberFormat;->format(D)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p2

    sub-int/2addr p2, p3

    invoke-virtual {p1, p2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method private log(I)Ljava/lang/String;
    .locals 3

    .line 36
    invoke-virtual {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->getValue(I)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    move-result-object v0

    .line 37
    invoke-virtual {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->geName(I)Ljava/lang/String;

    move-result-object p1

    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v2, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->WORD_PAD:Ljava/lang/String;

    .line 39
    invoke-static {v1, v2, p1}, Lo/l;->i(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 40
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v1

    sget v2, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->MAX_WORD:I

    sub-int/2addr v1, v2

    invoke-virtual {p1, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p1

    .line 41
    const-string v1, " = "

    .line 42
    invoke-static {p1, v1}, Lo/l;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 43
    const-string v1, "CL Perf: "

    .line 44
    invoke-static {v1, p1, v0}, Lo/l;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method private log(Ljava/text/DecimalFormat;I)Ljava/lang/String;
    .locals 2

    .line 14
    invoke-virtual {p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->getValue(I)J

    move-result-wide v0

    long-to-float v0, v0

    const v1, 0x358637bd    # 1.0E-6f

    mul-float/2addr v0, v1

    const/4 v1, 0x7

    invoke-direct {p0, p1, v0, v1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->fmt(Ljava/text/DecimalFormat;FI)Ljava/lang/String;

    move-result-object p1

    .line 15
    invoke-virtual {p0, p2}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->geName(I)Ljava/lang/String;

    move-result-object p2

    .line 16
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->WORD_PAD:Ljava/lang/String;

    .line 17
    invoke-static {v0, v1, p2}, Lo/l;->i(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 18
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    sget v1, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->MAX_WORD:I

    sub-int/2addr v0, v1

    invoke-virtual {p2, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p2

    .line 19
    const-string v0, " = "

    .line 20
    invoke-static {p2, v0}, Lo/l;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    .line 21
    const-string v0, "CL Perf: "

    .line 22
    invoke-static {v0, p2, p1}, Lo/l;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method private log(Ljava/lang/String;)V
    .locals 2
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "LogConditional"
        }
    .end annotation

    .line 1
    new-instance p1, Ljava/lang/Throwable;

    invoke-direct {p1}, Ljava/lang/Throwable;-><init>()V

    invoke-virtual {p1}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    move-result-object p1

    const/4 v0, 0x2

    aget-object p1, p1, v0

    .line 2
    invoke-virtual {p1}, Ljava/lang/StackTraceElement;->getFileName()Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/StackTraceElement;->getLineNumber()I

    .line 3
    new-instance p1, Ljava/text/DecimalFormat;

    const-string v1, "###.000"

    invoke-direct {p1, v1}, Ljava/text/DecimalFormat;-><init>(Ljava/lang/String;)V

    const/4 v1, 0x5

    .line 4
    invoke-direct {p0, p1, v1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(Ljava/text/DecimalFormat;I)Ljava/lang/String;

    const/4 v1, 0x7

    .line 5
    invoke-direct {p0, p1, v1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(Ljava/text/DecimalFormat;I)Ljava/lang/String;

    const/4 v1, 0x6

    .line 6
    invoke-direct {p0, p1, v1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(Ljava/text/DecimalFormat;I)Ljava/lang/String;

    const/4 p1, 0x1

    .line 7
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    .line 8
    invoke-direct {p0, v0}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    const/4 p1, 0x3

    .line 9
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    const/4 p1, 0x4

    .line 10
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    const/16 p1, 0x8

    .line 11
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    const/16 p1, 0x9

    .line 12
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    const/16 p1, 0xa

    .line 13
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(I)Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public attach(Landroidx/constraintlayout/widget/ConstraintLayout;)V
    .locals 1

    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    invoke-virtual {p1, v0}, Landroidx/constraintlayout/widget/ConstraintLayout;->fillMetrics(Landroidx/constraintlayout/core/Metrics;)V

    iput-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mConstraintLayout:Landroidx/constraintlayout/widget/ConstraintLayout;

    return-void
.end method

.method public clone()Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;
    .locals 1

    .line 2
    new-instance v0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;

    invoke-direct {v0, p0}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;-><init>(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;)V

    return-object v0
.end method

.method public bridge synthetic clone()Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->clone()Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;

    move-result-object v0

    return-object v0
.end method

.method public detach()V
    .locals 2

    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mConstraintLayout:Landroidx/constraintlayout/widget/ConstraintLayout;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/constraintlayout/widget/ConstraintLayout;->fillMetrics(Landroidx/constraintlayout/core/Metrics;)V

    :cond_0
    return-void
.end method

.method public geName(I)Ljava/lang/String;
    .locals 0

    packed-switch p1, :pswitch_data_0

    const-string p1, ""

    return-object p1

    :pswitch_0
    const-string p1, "SimpleEquations"

    return-object p1

    :pswitch_1
    const-string p1, "SolverEquations"

    return-object p1

    :pswitch_2
    const-string p1, "SolverVariables"

    return-object p1

    :pswitch_3
    const-string p1, "MeasuresLayoutDuration"

    return-object p1

    :pswitch_4
    const-string p1, "MeasureDuration"

    return-object p1

    :pswitch_5
    const-string p1, "MeasuresWidgetsDuration "

    return-object p1

    :pswitch_6
    const-string p1, "ChildrenMeasures"

    return-object p1

    :pswitch_7
    const-string p1, "ChildCount"

    return-object p1

    :pswitch_8
    const-string p1, "MeasureCalls"

    return-object p1

    :pswitch_9
    const-string p1, "NumberOfLayouts"

    return-object p1

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public getValue(I)J
    .locals 2

    packed-switch p1, :pswitch_data_0

    const-wide/16 v0, 0x0

    return-wide v0

    :pswitch_0
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->mSimpleEquations:J

    return-wide v0

    :pswitch_1
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->mEquations:J

    return-wide v0

    :pswitch_2
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->mVariables:J

    return-wide v0

    :pswitch_3
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->measuresLayoutDuration:J

    return-wide v0

    :pswitch_4
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->mMeasureDuration:J

    return-wide v0

    :pswitch_5
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->measuresWidgetsDuration:J

    return-wide v0

    :pswitch_6
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget p1, p1, Landroidx/constraintlayout/core/Metrics;->mNumberOfMeasures:I

    int-to-long v0, p1

    return-wide v0

    :pswitch_7
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->mChildCount:J

    return-wide v0

    :pswitch_8
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget-wide v0, p1, Landroidx/constraintlayout/core/Metrics;->mMeasureCalls:J

    return-wide v0

    :pswitch_9
    iget-object p1, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    iget p1, p1, Landroidx/constraintlayout/core/Metrics;->mNumberOfLayouts:I

    int-to-long v0, p1

    return-wide v0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public logSummary(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(Ljava/lang/String;)V

    return-void
.end method

.method public logSummary(Ljava/lang/String;Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;)V
    .locals 2
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "LogConditional"
        }
    .end annotation

    if-nez p2, :cond_0

    .line 2
    invoke-direct {p0, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->log(Ljava/lang/String;)V

    return-void

    .line 3
    :cond_0
    new-instance p1, Ljava/text/DecimalFormat;

    const-string v0, "###.000"

    invoke-direct {p1, v0}, Ljava/text/DecimalFormat;-><init>(Ljava/lang/String;)V

    .line 4
    new-instance v0, Ljava/lang/Throwable;

    invoke-direct {v0}, Ljava/lang/Throwable;-><init>()V

    invoke-virtual {v0}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    move-result-object v0

    const/4 v1, 0x1

    aget-object v0, v0, v1

    .line 5
    invoke-virtual {v0}, Ljava/lang/StackTraceElement;->getFileName()Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/StackTraceElement;->getLineNumber()I

    const/4 v0, 0x5

    .line 6
    invoke-direct {p0, p1, p2, v0}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Ljava/text/DecimalFormat;Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/4 v0, 0x7

    .line 7
    invoke-direct {p0, p1, p2, v0}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Ljava/text/DecimalFormat;Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/4 v0, 0x6

    .line 8
    invoke-direct {p0, p1, p2, v0}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Ljava/text/DecimalFormat;Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    .line 9
    invoke-direct {p0, p2, v1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/4 p1, 0x3

    .line 11
    invoke-direct {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/4 p1, 0x4

    .line 12
    invoke-direct {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/16 p1, 0x8

    .line 13
    invoke-direct {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/16 p1, 0x9

    .line 14
    invoke-direct {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    const/16 p1, 0xa

    .line 15
    invoke-direct {p0, p2, p1}, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->compare(Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;I)Ljava/lang/String;

    return-void
.end method

.method public reset()V
    .locals 1

    iget-object v0, p0, Landroidx/constraintlayout/widget/ConstraintLayoutStatistics;->mMetrics:Landroidx/constraintlayout/core/Metrics;

    invoke-virtual {v0}, Landroidx/constraintlayout/core/Metrics;->reset()V

    return-void
.end method

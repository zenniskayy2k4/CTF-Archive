.class public final Lo/q5;
.super Lo/K0;
.source "SourceFile"


# static fields
.field public static final a:Lo/q5;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lo/q5;

    invoke-direct {v0}, Lo/K0;-><init>()V

    sput-object v0, Lo/q5;->a:Lo/q5;

    return-void
.end method


# virtual methods
.method public final dispatch(Lo/H0;Ljava/lang/Runnable;)V
    .locals 2

    sget-object p1, Lo/b1;->b:Lo/b1;

    sget-object v0, Lo/d5;->h:Lo/b5;

    iget-object p1, p1, Lo/v4;->a:Lo/O0;

    const/4 v1, 0x0

    invoke-virtual {p1, p2, v0, v1}, Lo/O0;->b(Ljava/lang/Runnable;Lo/b5;Z)V

    return-void
.end method

.method public final dispatchYield(Lo/H0;Ljava/lang/Runnable;)V
    .locals 2

    sget-object p1, Lo/b1;->b:Lo/b1;

    sget-object v0, Lo/d5;->h:Lo/b5;

    iget-object p1, p1, Lo/v4;->a:Lo/O0;

    const/4 v1, 0x1

    invoke-virtual {p1, p2, v0, v1}, Lo/O0;->b(Ljava/lang/Runnable;Lo/b5;Z)V

    return-void
.end method

.method public final limitedParallelism(I)Lo/K0;
    .locals 1

    invoke-static {p1}, Lo/G4;->d(I)V

    sget v0, Lo/d5;->d:I

    if-lt p1, v0, :cond_0

    return-object p0

    :cond_0
    invoke-super {p0, p1}, Lo/K0;->limitedParallelism(I)Lo/K0;

    move-result-object p1

    return-object p1
.end method

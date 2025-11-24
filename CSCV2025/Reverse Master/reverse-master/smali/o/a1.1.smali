.class public final Lo/a1;
.super Lo/y1;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static final a:Lo/a1;

.field public static final b:Lo/K0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Lo/a1;

    invoke-direct {v0}, Lo/K0;-><init>()V

    sput-object v0, Lo/a1;->a:Lo/a1;

    sget-object v0, Lo/q5;->a:Lo/q5;

    sget v1, Lo/Z4;->a:I

    const/16 v2, 0x40

    if-ge v2, v1, :cond_0

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    const/16 v2, 0xc

    const-string v3, "kotlinx.coroutines.io.parallelism"

    invoke-static {v3, v1, v2}, Lo/G4;->m(Ljava/lang/String;II)I

    move-result v1

    invoke-virtual {v0, v1}, Lo/q5;->limitedParallelism(I)Lo/K0;

    move-result-object v0

    sput-object v0, Lo/a1;->b:Lo/K0;

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot be invoked on Dispatchers.IO"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final dispatch(Lo/H0;Ljava/lang/Runnable;)V
    .locals 1

    sget-object v0, Lo/a1;->b:Lo/K0;

    invoke-virtual {v0, p1, p2}, Lo/K0;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final dispatchYield(Lo/H0;Ljava/lang/Runnable;)V
    .locals 1

    sget-object v0, Lo/a1;->b:Lo/K0;

    invoke-virtual {v0, p1, p2}, Lo/K0;->dispatchYield(Lo/H0;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final execute(Ljava/lang/Runnable;)V
    .locals 1

    sget-object v0, Lo/p1;->a:Lo/p1;

    invoke-virtual {p0, v0, p1}, Lo/a1;->dispatch(Lo/H0;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final limitedParallelism(I)Lo/K0;
    .locals 1

    sget-object v0, Lo/q5;->a:Lo/q5;

    invoke-virtual {v0, p1}, Lo/q5;->limitedParallelism(I)Lo/K0;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Dispatchers.IO"

    return-object v0
.end method

.class public final Lo/b1;
.super Lo/v4;
.source "SourceFile"


# static fields
.field public static final b:Lo/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Lo/b1;

    sget v2, Lo/d5;->c:I

    sget v3, Lo/d5;->d:I

    sget-wide v4, Lo/d5;->e:J

    sget-object v6, Lo/d5;->a:Ljava/lang/String;

    invoke-direct {v0}, Lo/K0;-><init>()V

    new-instance v1, Lo/O0;

    invoke-direct/range {v1 .. v6}, Lo/O0;-><init>(IIJLjava/lang/String;)V

    iput-object v1, v0, Lo/v4;->a:Lo/O0;

    sput-object v0, Lo/b1;->b:Lo/b1;

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 2

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    const-string v1, "Dispatchers.Default cannot be closed"

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final limitedParallelism(I)Lo/K0;
    .locals 1

    invoke-static {p1}, Lo/G4;->d(I)V

    sget v0, Lo/d5;->c:I

    if-lt p1, v0, :cond_0

    return-object p0

    :cond_0
    invoke-super {p0, p1}, Lo/K0;->limitedParallelism(I)Lo/K0;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Dispatchers.Default"

    return-object v0
.end method

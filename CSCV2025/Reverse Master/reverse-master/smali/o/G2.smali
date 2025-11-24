.class public final Lo/G2;
.super Lo/q4;
.source "SourceFile"


# instance fields
.field public a:I

.field public final synthetic b:Lo/W1;

.field public final synthetic c:Lo/B0;


# direct methods
.method public constructor <init>(Lo/B0;Lo/B0;Lo/W1;)V
    .locals 0

    iput-object p3, p0, Lo/G2;->b:Lo/W1;

    iput-object p2, p0, Lo/G2;->c:Lo/B0;

    invoke-direct {p0, p1}, Lo/q4;-><init>(Lo/B0;)V

    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Lo/G2;->a:I

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    if-ne v0, v1, :cond_0

    const/4 v0, 0x2

    iput v0, p0, Lo/G2;->a:I

    invoke-static {p1}, Lo/F2;->q(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "This coroutine had already completed"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iput v1, p0, Lo/G2;->a:I

    invoke-static {p1}, Lo/F2;->q(Ljava/lang/Object;)V

    iget-object p1, p0, Lo/G2;->b:Lo/W1;

    const-string v0, "null cannot be cast to non-null type kotlin.Function2<R of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted$lambda$1, kotlin.coroutines.Continuation<T of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted$lambda$1>, kotlin.Any?>"

    invoke-static {p1, v0}, Lo/F2;->d(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Lo/G4;->b(Ljava/lang/Object;)V

    iget-object v0, p0, Lo/G2;->c:Lo/B0;

    invoke-interface {p1, v0, p0}, Lo/W1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

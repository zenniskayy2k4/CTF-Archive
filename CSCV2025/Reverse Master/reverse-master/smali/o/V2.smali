.class public final Lo/V2;
.super Lo/I;
.source "SourceFile"


# instance fields
.field public final b:Lo/S2;

.field public c:Lo/R3;

.field public final synthetic d:Lo/W2;

.field public final synthetic e:Lo/u2;


# direct methods
.method public constructor <init>(Lo/S2;Lo/W2;Lo/u2;)V
    .locals 0

    iput-object p2, p0, Lo/V2;->d:Lo/W2;

    iput-object p3, p0, Lo/V2;->e:Lo/u2;

    invoke-direct {p0}, Lo/I;-><init>()V

    iput-object p1, p0, Lo/V2;->b:Lo/S2;

    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 4

    check-cast p1, Lo/t3;

    if-nez p2, :cond_0

    const/4 p2, 0x1

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    iget-object v0, p0, Lo/V2;->b:Lo/S2;

    if-eqz p2, :cond_1

    move-object v1, v0

    goto :goto_1

    :cond_1
    iget-object v1, p0, Lo/V2;->c:Lo/R3;

    :goto_1
    if-eqz v1, :cond_4

    sget-object v2, Lo/t3;->a:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    :cond_2
    invoke-virtual {v2, p1, p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    if-eqz p2, :cond_4

    iget-object p1, p0, Lo/V2;->c:Lo/R3;

    invoke-static {p1}, Lo/F2;->c(Ljava/lang/Object;)V

    invoke-virtual {v0, p1}, Lo/t3;->f(Lo/t3;)V

    return-void

    :cond_3
    invoke-virtual {v2, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-eq v3, p0, :cond_2

    :cond_4
    return-void
.end method

.method public final c(Ljava/lang/Object;)Lo/Q;
    .locals 1

    check-cast p1, Lo/t3;

    iget-object p1, p0, Lo/V2;->d:Lo/W2;

    invoke-virtual {p1}, Lo/W2;->p()Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Lo/V2;->e:Lo/u2;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    sget-object p1, Lo/G4;->c:Lo/Q;

    return-object p1
.end method

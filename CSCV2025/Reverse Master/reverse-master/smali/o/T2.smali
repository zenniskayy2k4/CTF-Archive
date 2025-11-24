.class public final Lo/T2;
.super Lo/S2;
.source "SourceFile"


# instance fields
.field public final e:Lo/W2;

.field public final f:Lo/U2;

.field public final g:Lo/a0;

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lo/W2;Lo/U2;Lo/a0;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Lo/t3;-><init>()V

    iput-object p1, p0, Lo/T2;->e:Lo/W2;

    iput-object p2, p0, Lo/T2;->f:Lo/U2;

    iput-object p3, p0, Lo/T2;->g:Lo/a0;

    iput-object p4, p0, Lo/T2;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/Throwable;)V
    .locals 7

    iget-object p1, p0, Lo/T2;->g:Lo/a0;

    iget-object v0, p0, Lo/T2;->e:Lo/W2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Lo/W2;->w(Lo/t3;)Lo/a0;

    move-result-object p1

    iget-object v1, p0, Lo/T2;->f:Lo/U2;

    iget-object v2, p0, Lo/T2;->h:Ljava/lang/Object;

    if-eqz p1, :cond_2

    :cond_0
    iget-object v3, p1, Lo/a0;->e:Lo/W2;

    new-instance v4, Lo/T2;

    invoke-direct {v4, v0, v1, p1, v2}, Lo/T2;-><init>(Lo/W2;Lo/U2;Lo/a0;Ljava/lang/Object;)V

    const/4 v5, 0x0

    const/4 v6, 0x1

    invoke-static {v3, v5, v4, v6}, Lo/W0;->f(Lo/O2;ZLo/S2;I)Lo/k1;

    move-result-object v3

    sget-object v4, Lo/S3;->a:Lo/S3;

    if-eq v3, v4, :cond_1

    return-void

    :cond_1
    invoke-static {p1}, Lo/W2;->w(Lo/t3;)Lo/a0;

    move-result-object p1

    if-nez p1, :cond_0

    :cond_2
    invoke-virtual {v0, v1, v2}, Lo/W2;->l(Lo/U2;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Lo/W2;->d(Ljava/lang/Object;)V

    return-void
.end method

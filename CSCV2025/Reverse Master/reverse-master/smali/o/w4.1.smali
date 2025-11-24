.class public Lo/w4;
.super Lo/c;
.source "SourceFile"

# interfaces
.implements Lo/R0;


# instance fields
.field public final d:Lo/B0;


# direct methods
.method public constructor <init>(Lo/B0;Lo/H0;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, p2, v0}, Lo/c;-><init>(Lo/H0;Z)V

    iput-object p1, p0, Lo/w4;->d:Lo/B0;

    return-void
.end method


# virtual methods
.method public d(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Lo/w4;->d:Lo/B0;

    invoke-static {v0}, Lo/F2;->l(Lo/B0;)Lo/B0;

    move-result-object v0

    invoke-static {p1}, Lo/G4;->h(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v0}, Lo/G4;->k(Ljava/lang/Object;Lo/B0;)V

    return-void
.end method

.method public e(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Lo/w4;->d:Lo/B0;

    invoke-static {p1}, Lo/G4;->h(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {v0, p1}, Lo/B0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public final getCallerFrame()Lo/R0;
    .locals 2

    iget-object v0, p0, Lo/w4;->d:Lo/B0;

    instance-of v1, v0, Lo/R0;

    if-eqz v1, :cond_0

    check-cast v0, Lo/R0;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final u()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

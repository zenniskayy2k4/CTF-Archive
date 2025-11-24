.class public abstract Lo/C0;
.super Lo/J;
.source "SourceFile"


# instance fields
.field private final _context:Lo/H0;

.field private transient intercepted:Lo/B0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lo/B0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lo/B0;)V
    .locals 1

    if-eqz p1, :cond_0

    .line 3
    invoke-interface {p1}, Lo/B0;->getContext()Lo/H0;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-direct {p0, p1, v0}, Lo/C0;-><init>(Lo/B0;Lo/H0;)V

    return-void
.end method

.method public constructor <init>(Lo/B0;Lo/H0;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lo/J;-><init>(Lo/B0;)V

    .line 2
    iput-object p2, p0, Lo/C0;->_context:Lo/H0;

    return-void
.end method


# virtual methods
.method public getContext()Lo/H0;
    .locals 1

    iget-object v0, p0, Lo/C0;->_context:Lo/H0;

    invoke-static {v0}, Lo/F2;->c(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final intercepted()Lo/B0;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lo/B0;"
        }
    .end annotation

    iget-object v0, p0, Lo/C0;->intercepted:Lo/B0;

    if-nez v0, :cond_2

    invoke-virtual {p0}, Lo/C0;->getContext()Lo/H0;

    move-result-object v0

    sget-object v1, Lo/D0;->a:Lo/D0;

    invoke-interface {v0, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v0

    check-cast v0, Lo/E0;

    if-eqz v0, :cond_0

    invoke-interface {v0, p0}, Lo/E0;->interceptContinuation(Lo/B0;)Lo/B0;

    move-result-object v0

    if-nez v0, :cond_1

    :cond_0
    move-object v0, p0

    :cond_1
    iput-object v0, p0, Lo/C0;->intercepted:Lo/B0;

    :cond_2
    return-object v0
.end method

.method public releaseIntercepted()V
    .locals 3

    iget-object v0, p0, Lo/C0;->intercepted:Lo/B0;

    if-eqz v0, :cond_0

    if-eq v0, p0, :cond_0

    invoke-virtual {p0}, Lo/C0;->getContext()Lo/H0;

    move-result-object v1

    sget-object v2, Lo/D0;->a:Lo/D0;

    invoke-interface {v1, v2}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v1

    invoke-static {v1}, Lo/F2;->c(Ljava/lang/Object;)V

    check-cast v1, Lo/E0;

    invoke-interface {v1, v0}, Lo/E0;->releaseInterceptedContinuation(Lo/B0;)V

    :cond_0
    sget-object v0, Lo/p0;->a:Lo/p0;

    iput-object v0, p0, Lo/C0;->intercepted:Lo/B0;

    return-void
.end method

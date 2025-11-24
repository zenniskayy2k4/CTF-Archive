.class public abstract Lo/v4;
.super Lo/y1;
.source "SourceFile"


# instance fields
.field public a:Lo/O0;


# virtual methods
.method public final dispatch(Lo/H0;Ljava/lang/Runnable;)V
    .locals 1

    const/4 p1, 0x6

    iget-object v0, p0, Lo/v4;->a:Lo/O0;

    invoke-static {v0, p2, p1}, Lo/O0;->c(Lo/O0;Ljava/lang/Runnable;I)V

    return-void
.end method

.method public final dispatchYield(Lo/H0;Ljava/lang/Runnable;)V
    .locals 1

    const/4 p1, 0x2

    iget-object v0, p0, Lo/v4;->a:Lo/O0;

    invoke-static {v0, p2, p1}, Lo/O0;->c(Lo/O0;Ljava/lang/Runnable;I)V

    return-void
.end method

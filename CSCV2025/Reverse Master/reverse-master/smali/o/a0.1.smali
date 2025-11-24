.class public final Lo/a0;
.super Lo/Q2;
.source "SourceFile"

# interfaces
.implements Lo/Z;


# instance fields
.field public final e:Lo/W2;


# direct methods
.method public constructor <init>(Lo/W2;)V
    .locals 0

    invoke-direct {p0}, Lo/t3;-><init>()V

    iput-object p1, p0, Lo/a0;->e:Lo/W2;

    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Throwable;)Z
    .locals 1

    invoke-virtual {p0}, Lo/S2;->j()Lo/W2;

    move-result-object v0

    invoke-virtual {v0, p1}, Lo/W2;->i(Ljava/lang/Throwable;)Z

    move-result p1

    return p1
.end method

.method public final c(Ljava/lang/Throwable;)V
    .locals 1

    invoke-virtual {p0}, Lo/S2;->j()Lo/W2;

    move-result-object p1

    iget-object v0, p0, Lo/a0;->e:Lo/W2;

    invoke-virtual {v0, p1}, Lo/W2;->f(Ljava/lang/Object;)Z

    return-void
.end method

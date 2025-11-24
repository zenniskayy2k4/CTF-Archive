.class public abstract Lo/F4;
.super Lo/G4;
.source "SourceFile"


# direct methods
.method public static q(Lo/C1;)Ljava/lang/Object;
    .locals 1

    new-instance v0, Lo/B1;

    invoke-direct {v0, p0}, Lo/B1;-><init>(Lo/C1;)V

    invoke-virtual {v0}, Lo/B1;->hasNext()Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    invoke-virtual {v0}, Lo/B1;->next()Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static r(Ljava/lang/Object;Lo/S1;)Lo/C4;
    .locals 2

    const-string v0, "nextFunction"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p0, :cond_0

    sget-object p0, Lo/t1;->a:Lo/t1;

    return-object p0

    :cond_0
    new-instance v0, Lo/k2;

    new-instance v1, Lo/H4;

    invoke-direct {v1, p0}, Lo/H4;-><init>(Ljava/lang/Object;)V

    invoke-direct {v0, v1, p1}, Lo/k2;-><init>(Lo/H4;Lo/S1;)V

    return-object v0
.end method

.method public static s(Lo/C4;Lo/S1;)Lo/C1;
    .locals 1

    const-string v0, "transform"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lo/k2;

    invoke-direct {v0, p0, p1}, Lo/k2;-><init>(Lo/C4;Lo/S1;)V

    new-instance p0, Lo/C1;

    const/4 p1, 0x0

    invoke-direct {p0, p1, v0}, Lo/C1;-><init>(ILjava/lang/Object;)V

    return-object p0
.end method

.method public static t(Lo/C4;)Ljava/util/List;
    .locals 2

    invoke-interface {p0}, Lo/C4;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-nez v0, :cond_0

    sget-object p0, Lo/r1;->a:Lo/r1;

    return-object p0

    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-static {v0}, Lo/F2;->m(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object v1
.end method

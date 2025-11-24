.class public abstract Lo/W0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Lo/Q;

.field public static final b:Lo/Q;

.field public static final c:Lo/P3;

.field public static d:Lo/P3;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    new-instance v0, Lo/Q;

    const-string v1, "NO_DECISION"

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/W0;->a:Lo/Q;

    new-instance v0, Lo/Q;

    const-string v1, "CLOSED_EMPTY"

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/W0;->b:Lo/Q;

    new-instance v0, Lo/P3;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1, v1}, Lo/P3;-><init>(Ljava/lang/reflect/Method;Ljava/lang/reflect/Method;Ljava/lang/reflect/Method;)V

    sput-object v0, Lo/W0;->c:Lo/P3;

    return-void
.end method

.method public static final a([Ljava/lang/Object;IILjava/util/List;)Z
    .locals 4

    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v0

    const/4 v1, 0x0

    if-eq p2, v0, :cond_0

    goto :goto_1

    :cond_0
    move v0, v1

    :goto_0
    if-ge v0, p2, :cond_2

    add-int v2, p1, v0

    aget-object v2, p0, v2

    invoke-interface {p3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2, v3}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1

    :goto_1
    return v1

    :cond_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    const/4 p0, 0x1

    return p0
.end method

.method public static final b([Ljava/lang/Object;IILo/j;)Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    mul-int/lit8 v1, p2, 0x3

    add-int/lit8 v1, v1, 0x2

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v1, "["

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/4 v1, 0x0

    :goto_0
    if-ge v1, p2, :cond_2

    if-lez v1, :cond_0

    const-string v2, ", "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    add-int v2, p1, v1

    aget-object v2, p0, v2

    if-ne v2, p3, :cond_1

    const-string v2, "(this Collection)"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_1
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    :goto_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    const-string p0, "]"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string p1, "toString(...)"

    invoke-static {p0, p1}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static c(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "exception"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    if-eq p0, p1, :cond_2

    sget-object v0, Lo/M2;->a:Ljava/lang/Integer;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    const/16 v1, 0x13

    if-lt v0, v1, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Lo/Y3;->a:Ljava/lang/reflect/Method;

    if-eqz v0, :cond_2

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_1
    :goto_0
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :cond_2
    return-void
.end method

.method public static final d(Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final e(Lo/H0;Ljava/lang/Throwable;)V
    .locals 4

    sget-object v0, Lo/L0;->a:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lo/u;

    :try_start_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    if-ne p1, v1, :cond_0

    move-object v2, p1

    goto :goto_1

    :cond_0
    new-instance v2, Ljava/lang/RuntimeException;

    const-string v3, "Exception while trying to handle coroutine exception"

    invoke-direct {v2, v3, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-static {v2, p1}, Lo/W0;->c(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v3

    invoke-interface {v3, v1, v2}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    goto :goto_0

    :cond_1
    :try_start_1
    new-instance v0, Lo/e1;

    invoke-direct {v0, p0}, Lo/e1;-><init>(Lo/H0;)V

    invoke-static {p1, v0}, Lo/W0;->c(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v0

    invoke-interface {v0, p0, p1}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static f(Lo/O2;ZLo/S2;I)Lo/k1;
    .locals 8

    and-int/lit8 v0, p3, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move p1, v1

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    const/4 v1, 0x1

    :cond_1
    instance-of p3, p0, Lo/W2;

    if-eqz p3, :cond_2

    check-cast p0, Lo/W2;

    invoke-virtual {p0, p1, v1, p2}, Lo/W2;->t(ZZLo/E2;)Lo/k1;

    move-result-object p0

    return-object p0

    :cond_2
    new-instance v2, Lo/R2;

    const/4 v3, 0x1

    const-string v7, "invoke(Ljava/lang/Throwable;)V"

    const-class v5, Lo/E2;

    const-string v6, "invoke"

    move-object v4, p2

    invoke-direct/range {v2 .. v7}, Lo/h2;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)V

    check-cast p0, Lo/W2;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Lo/D2;

    invoke-direct {p2, v2}, Lo/D2;-><init>(Lo/R2;)V

    invoke-virtual {p0, p1, v1, p2}, Lo/W2;->t(ZZLo/E2;)Lo/k1;

    move-result-object p0

    return-object p0
.end method

.method public static g(Lo/H0;Lo/H0;)Lo/H0;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Lo/p1;->a:Lo/p1;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    sget-object v0, Lo/m0;->c:Lo/m0;

    invoke-interface {p1, p0, v0}, Lo/H0;->fold(Ljava/lang/Object;Lo/W1;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lo/H0;

    return-object p0
.end method

.method public static h(Lo/W1;Lo/c;Lo/c;)V
    .locals 0

    :try_start_0
    invoke-static {p1, p2, p0}, Lo/F2;->g(Lo/B0;Lo/B0;Lo/W1;)Lo/B0;

    move-result-object p0

    invoke-static {p0}, Lo/F2;->l(Lo/B0;)Lo/B0;

    move-result-object p0

    sget-object p1, Lo/p5;->a:Lo/p5;

    invoke-static {p1, p0}, Lo/G4;->k(Ljava/lang/Object;Lo/B0;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p0

    invoke-static {p0}, Lo/F2;->h(Ljava/lang/Throwable;)Lo/s4;

    move-result-object p1

    invoke-virtual {p2, p1}, Lo/c;->resumeWith(Ljava/lang/Object;)V

    throw p0
.end method

.method public static final i(Lo/w4;Lo/w4;Lo/W1;)Ljava/lang/Object;
    .locals 1

    :try_start_0
    instance-of v0, p2, Lo/J;

    if-nez v0, :cond_0

    invoke-static {p2, p1, p0}, Lo/F2;->t(Lo/W1;Lo/c;Lo/c;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-static {p2}, Lo/G4;->b(Ljava/lang/Object;)V

    invoke-interface {p2, p1, p0}, Lo/W1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    new-instance p2, Lo/q0;

    const/4 v0, 0x0

    invoke-direct {p2, v0, p1}, Lo/q0;-><init>(ZLjava/lang/Throwable;)V

    move-object p1, p2

    :goto_0
    sget-object p2, Lo/Q0;->a:Lo/Q0;

    if-ne p1, p2, :cond_1

    goto :goto_3

    :cond_1
    invoke-virtual {p0, p1}, Lo/W2;->v(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Lo/F2;->c:Lo/Q;

    if-ne p0, p1, :cond_2

    goto :goto_3

    :cond_2
    instance-of p1, p0, Lo/q0;

    if-nez p1, :cond_6

    instance-of p1, p0, Lo/v2;

    if-eqz p1, :cond_3

    move-object p1, p0

    check-cast p1, Lo/v2;

    goto :goto_1

    :cond_3
    const/4 p1, 0x0

    :goto_1
    if-eqz p1, :cond_5

    iget-object p1, p1, Lo/v2;->a:Lo/u2;

    if-nez p1, :cond_4

    goto :goto_2

    :cond_4
    move-object p2, p1

    goto :goto_3

    :cond_5
    :goto_2
    move-object p2, p0

    :goto_3
    return-object p2

    :cond_6
    check-cast p0, Lo/q0;

    iget-object p0, p0, Lo/q0;->a:Ljava/lang/Throwable;

    throw p0
.end method

.method public static final j(Lo/B0;)Ljava/lang/String;
    .locals 3

    instance-of v0, p0, Lo/g1;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    const/16 v0, 0x40

    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Lo/W0;->d(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    invoke-static {v1}, Lo/F2;->h(Ljava/lang/Throwable;)Lo/s4;

    move-result-object v1

    :goto_0
    invoke-static {v1}, Lo/t4;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v2

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p0}, Lo/W0;->d(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    :goto_1
    check-cast v1, Ljava/lang/String;

    return-object v1
.end method

.method public static k(II)Lo/z2;
    .locals 2

    const/high16 v0, -0x80000000

    if-gt p1, v0, :cond_0

    sget-object p0, Lo/z2;->d:Lo/z2;

    return-object p0

    :cond_0
    new-instance v0, Lo/z2;

    const/4 v1, 0x1

    sub-int/2addr p1, v1

    invoke-direct {v0, p0, p1, v1}, Lo/x2;-><init>(III)V

    return-object v0
.end method

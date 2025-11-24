.class public final Lo/M0;
.super Ljava/lang/Thread;
.source "SourceFile"


# static fields
.field public static final synthetic i:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final a:Lo/B5;

.field public final b:Lo/k4;

.field public c:Lo/N0;

.field public d:J

.field public e:J

.field public f:I

.field public g:Z

.field public final synthetic h:Lo/O0;

.field private volatile indexInArray:I

.field private volatile nextParkedWorker:Ljava/lang/Object;

.field private volatile synthetic workerCtl$volatile:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Lo/M0;

    const-string v1, "workerCtl$volatile"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/M0;->i:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Lo/O0;I)V
    .locals 2

    iput-object p1, p0, Lo/M0;->h:Lo/O0;

    invoke-direct {p0}, Ljava/lang/Thread;-><init>()V

    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setDaemon(Z)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/lang/Thread;->setContextClassLoader(Ljava/lang/ClassLoader;)V

    new-instance p1, Lo/B5;

    invoke-direct {p1}, Lo/B5;-><init>()V

    iput-object p1, p0, Lo/M0;->a:Lo/B5;

    new-instance p1, Lo/k4;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/M0;->b:Lo/k4;

    sget-object p1, Lo/N0;->d:Lo/N0;

    iput-object p1, p0, Lo/M0;->c:Lo/N0;

    sget-object p1, Lo/O0;->k:Lo/Q;

    iput-object p1, p0, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v0

    long-to-int p1, v0

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/16 p1, 0x2a

    :goto_0
    iput p1, p0, Lo/M0;->f:I

    invoke-virtual {p0, p2}, Lo/M0;->f(I)V

    return-void
.end method


# virtual methods
.method public final a(Z)Lo/a5;
    .locals 12

    iget-object v0, p0, Lo/M0;->c:Lo/N0;

    sget-object v1, Lo/N0;->a:Lo/N0;

    const/4 v2, 0x0

    iget-object v3, p0, Lo/M0;->a:Lo/B5;

    const/4 v4, 0x1

    iget-object v5, p0, Lo/M0;->h:Lo/O0;

    if-ne v0, v1, :cond_0

    goto/16 :goto_3

    :cond_0
    sget-object v0, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    :cond_1
    iget-object v7, p0, Lo/M0;->h:Lo/O0;

    invoke-virtual {v0, v7}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v8

    const-wide v10, 0x7ffffc0000000000L

    and-long/2addr v10, v8

    const/16 v6, 0x2a

    shr-long/2addr v10, v6

    long-to-int v6, v10

    if-nez v6, :cond_b

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :goto_0
    sget-object p1, Lo/B5;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/a5;

    if-nez v0, :cond_2

    goto :goto_1

    :cond_2
    iget-object v1, v0, Lo/a5;->b:Lo/b5;

    iget v1, v1, Lo/b5;->a:I

    if-ne v1, v4, :cond_5

    :cond_3
    invoke-virtual {p1, v3, v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    move-object v2, v0

    goto :goto_2

    :cond_4
    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eq v1, v0, :cond_3

    goto :goto_0

    :cond_5
    :goto_1
    sget-object p1, Lo/B5;->d:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p1, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p1

    sget-object v0, Lo/B5;->c:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v0

    :cond_6
    if-eq p1, v0, :cond_8

    sget-object v1, Lo/B5;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v1

    if-nez v1, :cond_7

    goto :goto_2

    :cond_7
    add-int/lit8 v0, v0, -0x1

    invoke-virtual {v3, v0, v4}, Lo/B5;->c(IZ)Lo/a5;

    move-result-object v1

    if-eqz v1, :cond_6

    move-object v2, v1

    :cond_8
    :goto_2
    if-nez v2, :cond_a

    iget-object p1, v5, Lo/O0;->f:Lo/l2;

    invoke-virtual {p1}, Lo/u3;->d()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lo/a5;

    if-nez p1, :cond_9

    invoke-virtual {p0, v4}, Lo/M0;->i(I)Lo/a5;

    move-result-object p1

    :cond_9
    return-object p1

    :cond_a
    return-object v2

    :cond_b
    const-wide v10, 0x40000000000L

    sub-long v10, v8, v10

    sget-object v6, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual/range {v6 .. v11}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v6

    if-eqz v6, :cond_1

    iput-object v1, p0, Lo/M0;->c:Lo/N0;

    :goto_3
    if-eqz p1, :cond_10

    iget p1, v5, Lo/O0;->a:I

    mul-int/lit8 p1, p1, 0x2

    invoke-virtual {p0, p1}, Lo/M0;->d(I)I

    move-result p1

    if-nez p1, :cond_c

    goto :goto_4

    :cond_c
    const/4 v4, 0x0

    :goto_4
    if-eqz v4, :cond_d

    invoke-virtual {p0}, Lo/M0;->e()Lo/a5;

    move-result-object p1

    if-eqz p1, :cond_d

    return-object p1

    :cond_d
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Lo/B5;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, v3, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->getAndSet(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lo/a5;

    if-nez p1, :cond_e

    invoke-virtual {v3}, Lo/B5;->b()Lo/a5;

    move-result-object p1

    :cond_e
    if-eqz p1, :cond_f

    return-object p1

    :cond_f
    if-nez v4, :cond_11

    invoke-virtual {p0}, Lo/M0;->e()Lo/a5;

    move-result-object p1

    if-eqz p1, :cond_11

    return-object p1

    :cond_10
    invoke-virtual {p0}, Lo/M0;->e()Lo/a5;

    move-result-object p1

    if-eqz p1, :cond_11

    return-object p1

    :cond_11
    const/4 p1, 0x3

    invoke-virtual {p0, p1}, Lo/M0;->i(I)Lo/a5;

    move-result-object p1

    return-object p1
.end method

.method public final b()I
    .locals 1

    iget v0, p0, Lo/M0;->indexInArray:I

    return v0
.end method

.method public final c()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    return-object v0
.end method

.method public final d(I)I
    .locals 3

    iget v0, p0, Lo/M0;->f:I

    shl-int/lit8 v1, v0, 0xd

    xor-int/2addr v0, v1

    shr-int/lit8 v1, v0, 0x11

    xor-int/2addr v0, v1

    shl-int/lit8 v1, v0, 0x5

    xor-int/2addr v0, v1

    iput v0, p0, Lo/M0;->f:I

    add-int/lit8 v1, p1, -0x1

    and-int v2, v1, p1

    if-nez v2, :cond_0

    and-int p1, v0, v1

    return p1

    :cond_0
    const v1, 0x7fffffff

    and-int/2addr v0, v1

    rem-int/2addr v0, p1

    return v0
.end method

.method public final e()Lo/a5;
    .locals 2

    const/4 v0, 0x2

    invoke-virtual {p0, v0}, Lo/M0;->d(I)I

    move-result v0

    iget-object v1, p0, Lo/M0;->h:Lo/O0;

    if-nez v0, :cond_1

    iget-object v0, v1, Lo/O0;->e:Lo/l2;

    invoke-virtual {v0}, Lo/u3;->d()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/a5;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    iget-object v0, v1, Lo/O0;->f:Lo/l2;

    invoke-virtual {v0}, Lo/u3;->d()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/a5;

    return-object v0

    :cond_1
    iget-object v0, v1, Lo/O0;->f:Lo/l2;

    invoke-virtual {v0}, Lo/u3;->d()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/a5;

    if-eqz v0, :cond_2

    return-object v0

    :cond_2
    iget-object v0, v1, Lo/O0;->e:Lo/l2;

    invoke-virtual {v0}, Lo/u3;->d()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lo/a5;

    return-object v0
.end method

.method public final f(I)V
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Lo/M0;->h:Lo/O0;

    iget-object v1, v1, Lo/O0;->d:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "-worker-"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    if-nez p1, :cond_0

    const-string v1, "TERMINATED"

    goto :goto_0

    :cond_0
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    iput p1, p0, Lo/M0;->indexInArray:I

    return-void
.end method

.method public final g(Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    return-void
.end method

.method public final h(Lo/N0;)Z
    .locals 6

    iget-object v0, p0, Lo/M0;->c:Lo/N0;

    sget-object v1, Lo/N0;->a:Lo/N0;

    if-ne v0, v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    if-eqz v1, :cond_1

    sget-object v2, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    const-wide v3, 0x40000000000L

    iget-object v5, p0, Lo/M0;->h:Lo/O0;

    invoke-virtual {v2, v5, v3, v4}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->addAndGet(Ljava/lang/Object;J)J

    :cond_1
    if-eq v0, p1, :cond_2

    iput-object p1, p0, Lo/M0;->c:Lo/N0;

    :cond_2
    return v1
.end method

.method public final i(I)Lo/a5;
    .locals 25

    move-object/from16 v0, p0

    move/from16 v1, p1

    sget-object v2, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    iget-object v3, v0, Lo/M0;->h:Lo/O0;

    invoke-virtual {v2, v3}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v4

    const-wide/32 v6, 0x1fffff

    and-long/2addr v4, v6

    long-to-int v2, v4

    const/4 v4, 0x2

    const/4 v5, 0x0

    if-ge v2, v4, :cond_0

    return-object v5

    :cond_0
    invoke-virtual {v0, v2}, Lo/M0;->d(I)I

    move-result v6

    const/4 v10, 0x0

    const-wide v11, 0x7fffffffffffffffL

    :goto_0
    if-ge v10, v2, :cond_10

    const/4 v15, 0x1

    add-int/2addr v6, v15

    if-le v6, v2, :cond_1

    move v6, v15

    :cond_1
    iget-object v4, v3, Lo/O0;->g:Lo/o4;

    invoke-virtual {v4, v6}, Lo/o4;->b(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lo/M0;

    if-eqz v4, :cond_e

    if-eq v4, v0, :cond_e

    const/4 v7, 0x3

    iget-object v4, v4, Lo/M0;->a:Lo/B5;

    if-ne v1, v7, :cond_2

    invoke-virtual {v4}, Lo/B5;->b()Lo/a5;

    move-result-object v7

    const-wide v16, 0x7fffffffffffffffL

    const-wide/16 v18, 0x0

    goto :goto_3

    :cond_2
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Lo/B5;->d:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v7, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v7

    const-wide v16, 0x7fffffffffffffffL

    sget-object v8, Lo/B5;->c:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v8, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v8

    if-ne v1, v15, :cond_3

    move v9, v15

    goto :goto_1

    :cond_3
    const/4 v9, 0x0

    :goto_1
    if-eq v7, v8, :cond_5

    const-wide/16 v18, 0x0

    if-eqz v9, :cond_4

    sget-object v13, Lo/B5;->e:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v13, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v13

    if-nez v13, :cond_4

    :goto_2
    move-object v7, v5

    goto :goto_3

    :cond_4
    add-int/lit8 v13, v7, 0x1

    invoke-virtual {v4, v7, v9}, Lo/B5;->c(IZ)Lo/a5;

    move-result-object v7

    if-nez v7, :cond_6

    move v7, v13

    goto :goto_1

    :cond_5
    const-wide/16 v18, 0x0

    goto :goto_2

    :cond_6
    :goto_3
    iget-object v13, v0, Lo/M0;->b:Lo/k4;

    if-eqz v7, :cond_7

    iput-object v7, v13, Lo/k4;->a:Ljava/lang/Object;

    move/from16 v23, v6

    const-wide/16 v7, -0x1

    const-wide/16 v20, -0x1

    goto :goto_7

    :cond_7
    :goto_4
    sget-object v7, Lo/B5;->b:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v7, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Lo/a5;

    if-nez v14, :cond_8

    const-wide/16 v20, -0x1

    goto :goto_6

    :cond_8
    const-wide/16 v20, -0x1

    iget-object v8, v14, Lo/a5;->b:Lo/b5;

    iget v8, v8, Lo/b5;->a:I

    if-ne v8, v15, :cond_9

    move v8, v15

    goto :goto_5

    :cond_9
    const/4 v8, 0x2

    :goto_5
    and-int/2addr v8, v1

    if-nez v8, :cond_a

    :goto_6
    const-wide/16 v7, -0x2

    move/from16 v23, v6

    goto :goto_7

    :cond_a
    sget-object v8, Lo/d5;->f:Lo/D0;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v8

    move/from16 v23, v6

    iget-wide v5, v14, Lo/a5;->a:J

    sub-long/2addr v8, v5

    sget-wide v5, Lo/d5;->b:J

    cmp-long v24, v8, v5

    if-gez v24, :cond_b

    sub-long v7, v5, v8

    const/4 v5, 0x0

    goto :goto_7

    :cond_b
    const/4 v5, 0x0

    invoke-virtual {v7, v4, v14, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_d

    iput-object v14, v13, Lo/k4;->a:Ljava/lang/Object;

    move-wide/from16 v7, v20

    :goto_7
    cmp-long v4, v7, v20

    if-nez v4, :cond_c

    iget-object v1, v13, Lo/k4;->a:Ljava/lang/Object;

    check-cast v1, Lo/a5;

    iput-object v5, v13, Lo/k4;->a:Ljava/lang/Object;

    return-object v1

    :cond_c
    cmp-long v4, v7, v18

    if-lez v4, :cond_f

    invoke-static {v11, v12, v7, v8}, Ljava/lang/Math;->min(JJ)J

    move-result-wide v11

    goto :goto_8

    :cond_d
    invoke-virtual {v7, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-eq v5, v14, :cond_b

    move/from16 v6, v23

    const/4 v5, 0x0

    goto :goto_4

    :cond_e
    move/from16 v23, v6

    const-wide v16, 0x7fffffffffffffffL

    :cond_f
    :goto_8
    add-int/lit8 v10, v10, 0x1

    move/from16 v6, v23

    const/4 v4, 0x2

    const/4 v5, 0x0

    goto/16 :goto_0

    :cond_10
    const-wide v16, 0x7fffffffffffffffL

    const-wide/16 v18, 0x0

    cmp-long v1, v11, v16

    if-eqz v1, :cond_11

    goto :goto_9

    :cond_11
    move-wide/from16 v11, v18

    :goto_9
    iput-wide v11, v0, Lo/M0;->e:J

    const/16 v22, 0x0

    return-object v22
.end method

.method public final run()V
    .locals 18

    move-object/from16 v1, p0

    const/4 v2, 0x0

    :cond_0
    :goto_0
    move v0, v2

    :cond_1
    :goto_1
    iget-object v3, v1, Lo/M0;->h:Lo/O0;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Lo/O0;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v4, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v3

    if-eqz v3, :cond_2

    goto/16 :goto_b

    :cond_2
    iget-object v3, v1, Lo/M0;->c:Lo/N0;

    sget-object v4, Lo/N0;->e:Lo/N0;

    if-eq v3, v4, :cond_18

    iget-boolean v3, v1, Lo/M0;->g:Z

    invoke-virtual {v1, v3}, Lo/M0;->a(Z)Lo/a5;

    move-result-object v3

    const-wide/32 v5, -0x200000

    const-wide/16 v7, 0x0

    if-eqz v3, :cond_9

    iput-wide v7, v1, Lo/M0;->e:J

    iget-object v0, v3, Lo/a5;->b:Lo/b5;

    iget v9, v0, Lo/b5;->a:I

    iput-wide v7, v1, Lo/M0;->d:J

    iget-object v0, v1, Lo/M0;->c:Lo/N0;

    sget-object v7, Lo/N0;->c:Lo/N0;

    if-ne v0, v7, :cond_3

    sget-object v0, Lo/N0;->b:Lo/N0;

    iput-object v0, v1, Lo/M0;->c:Lo/N0;

    :cond_3
    iget-object v7, v1, Lo/M0;->h:Lo/O0;

    if-nez v9, :cond_4

    goto :goto_2

    :cond_4
    sget-object v0, Lo/N0;->b:Lo/N0;

    invoke-virtual {v1, v0}, Lo/M0;->h(Lo/N0;)Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-virtual {v7}, Lo/O0;->f()Z

    move-result v0

    if-eqz v0, :cond_5

    goto :goto_2

    :cond_5
    sget-object v0, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, v7}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v10

    invoke-virtual {v7, v10, v11}, Lo/O0;->e(J)Z

    move-result v0

    if-eqz v0, :cond_6

    goto :goto_2

    :cond_6
    invoke-virtual {v7}, Lo/O0;->f()Z

    :cond_7
    :goto_2
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :try_start_0
    invoke-interface {v3}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    :catchall_0
    move-exception v0

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Thread;->getUncaughtExceptionHandler()Ljava/lang/Thread$UncaughtExceptionHandler;

    move-result-object v8

    invoke-interface {v8, v3, v0}, Ljava/lang/Thread$UncaughtExceptionHandler;->uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V

    :goto_3
    if-nez v9, :cond_8

    goto :goto_0

    :cond_8
    sget-object v0, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, v7, v5, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->addAndGet(Ljava/lang/Object;J)J

    iget-object v0, v1, Lo/M0;->c:Lo/N0;

    if-eq v0, v4, :cond_0

    sget-object v0, Lo/N0;->d:Lo/N0;

    iput-object v0, v1, Lo/M0;->c:Lo/N0;

    goto :goto_0

    :cond_9
    iput-boolean v2, v1, Lo/M0;->g:Z

    iget-wide v3, v1, Lo/M0;->e:J

    cmp-long v3, v3, v7

    const/4 v4, 0x1

    if-eqz v3, :cond_b

    if-nez v0, :cond_a

    move v0, v4

    goto/16 :goto_1

    :cond_a
    sget-object v0, Lo/N0;->c:Lo/N0;

    invoke-virtual {v1, v0}, Lo/M0;->h(Lo/N0;)Z

    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    iget-wide v3, v1, Lo/M0;->e:J

    invoke-static {v3, v4}, Ljava/util/concurrent/locks/LockSupport;->parkNanos(J)V

    iput-wide v7, v1, Lo/M0;->e:J

    goto/16 :goto_0

    :cond_b
    iget-object v3, v1, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    sget-object v9, Lo/O0;->k:Lo/Q;

    if-eq v3, v9, :cond_c

    move v3, v4

    goto :goto_4

    :cond_c
    move v3, v2

    :goto_4
    const-wide/32 v10, 0x1fffff

    if-nez v3, :cond_e

    iget-object v13, v1, Lo/M0;->h:Lo/O0;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v3, v1, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    if-eq v3, v9, :cond_d

    goto/16 :goto_1

    :cond_d
    sget-object v12, Lo/O0;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v12, v13}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v14

    and-long v3, v14, v10

    long-to-int v3, v3

    const-wide/32 v7, 0x200000

    add-long/2addr v7, v14

    and-long/2addr v7, v5

    iget v4, v1, Lo/M0;->indexInArray:I

    iget-object v9, v13, Lo/O0;->g:Lo/o4;

    invoke-virtual {v9, v3}, Lo/o4;->b(I)Ljava/lang/Object;

    move-result-object v3

    iput-object v3, v1, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    int-to-long v3, v4

    or-long v16, v7, v3

    invoke-virtual/range {v12 .. v17}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v3

    if-eqz v3, :cond_d

    goto/16 :goto_1

    :cond_e
    sget-object v3, Lo/M0;->i:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    const/4 v5, -0x1

    invoke-virtual {v3, v1, v5}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->set(Ljava/lang/Object;I)V

    :goto_5
    iget-object v3, v1, Lo/M0;->nextParkedWorker:Ljava/lang/Object;

    sget-object v6, Lo/O0;->k:Lo/Q;

    if-eq v3, v6, :cond_1

    sget-object v3, Lo/M0;->i:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v3, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v6

    if-ne v6, v5, :cond_1

    iget-object v6, v1, Lo/M0;->h:Lo/O0;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Lo/O0;->j:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v9, v6}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v6

    if-eqz v6, :cond_f

    goto/16 :goto_1

    :cond_f
    iget-object v6, v1, Lo/M0;->c:Lo/N0;

    sget-object v12, Lo/N0;->e:Lo/N0;

    if-ne v6, v12, :cond_10

    goto/16 :goto_1

    :cond_10
    sget-object v6, Lo/N0;->c:Lo/N0;

    invoke-virtual {v1, v6}, Lo/M0;->h(Lo/N0;)Z

    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    iget-wide v13, v1, Lo/M0;->d:J

    cmp-long v6, v13, v7

    if-nez v6, :cond_11

    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v13

    iget-object v6, v1, Lo/M0;->h:Lo/O0;

    move-wide v15, v10

    iget-wide v10, v6, Lo/O0;->c:J

    add-long/2addr v13, v10

    iput-wide v13, v1, Lo/M0;->d:J

    goto :goto_6

    :cond_11
    move-wide v15, v10

    :goto_6
    iget-object v6, v1, Lo/M0;->h:Lo/O0;

    iget-wide v10, v6, Lo/O0;->c:J

    invoke-static {v10, v11}, Ljava/util/concurrent/locks/LockSupport;->parkNanos(J)V

    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v10

    iget-wide v13, v1, Lo/M0;->d:J

    sub-long/2addr v10, v13

    cmp-long v6, v10, v7

    if-ltz v6, :cond_17

    iput-wide v7, v1, Lo/M0;->d:J

    iget-object v6, v1, Lo/M0;->h:Lo/O0;

    iget-object v10, v6, Lo/O0;->g:Lo/o4;

    monitor-enter v10

    :try_start_1
    invoke-virtual {v9, v6}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v9
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v9, :cond_12

    move v9, v4

    goto :goto_7

    :cond_12
    move v9, v2

    :goto_7
    if-eqz v9, :cond_13

    monitor-exit v10

    goto :goto_a

    :cond_13
    :try_start_2
    sget-object v9, Lo/O0;->i:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v9, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v13

    and-long/2addr v13, v15

    long-to-int v11, v13

    iget v13, v6, Lo/O0;->a:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    if-gt v11, v13, :cond_14

    monitor-exit v10

    goto :goto_a

    :cond_14
    :try_start_3
    invoke-virtual {v3, v1, v5, v4}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    move-result v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-nez v3, :cond_15

    monitor-exit v10

    goto :goto_a

    :cond_15
    :try_start_4
    iget v3, v1, Lo/M0;->indexInArray:I

    invoke-virtual {v1, v2}, Lo/M0;->f(I)V

    invoke-virtual {v6, v1, v3, v2}, Lo/O0;->d(Lo/M0;II)V

    invoke-virtual {v9, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->getAndDecrement(Ljava/lang/Object;)J

    move-result-wide v13

    and-long/2addr v13, v15

    long-to-int v9, v13

    if-eq v9, v3, :cond_16

    iget-object v11, v6, Lo/O0;->g:Lo/o4;

    invoke-virtual {v11, v9}, Lo/o4;->b(I)Ljava/lang/Object;

    move-result-object v11

    invoke-static {v11}, Lo/F2;->c(Ljava/lang/Object;)V

    check-cast v11, Lo/M0;

    iget-object v13, v6, Lo/O0;->g:Lo/o4;

    invoke-virtual {v13, v3, v11}, Lo/o4;->c(ILo/M0;)V

    invoke-virtual {v11, v3}, Lo/M0;->f(I)V

    invoke-virtual {v6, v11, v9, v3}, Lo/O0;->d(Lo/M0;II)V

    goto :goto_8

    :catchall_1
    move-exception v0

    goto :goto_9

    :cond_16
    :goto_8
    iget-object v3, v6, Lo/O0;->g:Lo/o4;

    const/4 v6, 0x0

    invoke-virtual {v3, v9, v6}, Lo/o4;->c(ILo/M0;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    monitor-exit v10

    iput-object v12, v1, Lo/M0;->c:Lo/N0;

    goto :goto_a

    :goto_9
    monitor-exit v10

    throw v0

    :cond_17
    :goto_a
    move-wide v10, v15

    goto/16 :goto_5

    :cond_18
    :goto_b
    sget-object v0, Lo/N0;->e:Lo/N0;

    invoke-virtual {v1, v0}, Lo/M0;->h(Lo/N0;)Z

    return-void
.end method

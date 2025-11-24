.class public final Lo/w3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final g:Lo/Q;


# instance fields
.field private volatile synthetic _next$volatile:Ljava/lang/Object;

.field private volatile synthetic _state$volatile:J

.field public final a:I

.field public final b:Z

.field public final c:I

.field public final synthetic d:Ljava/util/concurrent/atomic/AtomicReferenceArray;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-class v0, Lo/w3;

    const-class v1, Ljava/lang/Object;

    const-string v2, "_next$volatile"

    invoke-static {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v1

    sput-object v1, Lo/w3;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const-string v1, "_state$volatile"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    move-result-object v0

    sput-object v0, Lo/w3;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    new-instance v0, Lo/Q;

    const-string v1, "REMOVE_FROZEN"

    const/4 v2, 0x1

    invoke-direct {v0, v2, v1}, Lo/Q;-><init>(ILjava/lang/Object;)V

    sput-object v0, Lo/w3;->g:Lo/Q;

    return-void
.end method

.method public constructor <init>(IZ)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lo/w3;->a:I

    iput-boolean p2, p0, Lo/w3;->b:Z

    add-int/lit8 p2, p1, -0x1

    iput p2, p0, Lo/w3;->c:I

    new-instance v0, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;-><init>(I)V

    iput-object v0, p0, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    const v0, 0x3fffffff    # 1.9999999f

    const-string v1, "Check failed."

    if-gt p2, v0, :cond_1

    and-int/2addr p1, p2

    if-nez p1, :cond_0

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final a(Ljava/lang/Runnable;)I
    .locals 14

    :cond_0
    sget-object v0, Lo/w3;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v2

    const-wide/high16 v4, 0x3000000000000000L    # 1.727233711018889E-77

    and-long/2addr v4, v2

    const-wide/16 v6, 0x0

    cmp-long v1, v4, v6

    if-eqz v1, :cond_1

    const-wide/high16 v0, 0x2000000000000000L

    and-long/2addr v0, v2

    cmp-long p1, v0, v6

    if-eqz p1, :cond_3

    const/4 p1, 0x2

    return p1

    :cond_1
    const-wide/32 v4, 0x3fffffff

    and-long/2addr v4, v2

    long-to-int v1, v4

    const-wide v4, 0xfffffffc0000000L

    and-long/2addr v4, v2

    const/16 v8, 0x1e

    shr-long/2addr v4, v8

    long-to-int v9, v4

    add-int/lit8 v4, v9, 0x2

    iget v10, p0, Lo/w3;->c:I

    and-int/2addr v4, v10

    and-int v5, v1, v10

    if-ne v4, v5, :cond_2

    goto :goto_0

    :cond_2
    iget-object v11, p0, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    iget-boolean v4, p0, Lo/w3;->b:Z

    const v5, 0x3fffffff    # 1.9999999f

    if-nez v4, :cond_4

    and-int v4, v9, v10

    invoke-virtual {v11, v4}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_4

    const/16 v0, 0x400

    iget v2, p0, Lo/w3;->a:I

    if-lt v2, v0, :cond_3

    sub-int/2addr v9, v1

    and-int v0, v9, v5

    shr-int/lit8 v1, v2, 0x1

    if-le v0, v1, :cond_0

    :cond_3
    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_4
    add-int/lit8 v1, v9, 0x1

    and-int/2addr v1, v5

    const-wide v4, -0xfffffffc0000001L    # -3.1050369248997324E231

    and-long/2addr v4, v2

    int-to-long v12, v1

    shl-long/2addr v12, v8

    or-long/2addr v4, v12

    move-object v1, p0

    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v2

    if-eqz v2, :cond_0

    and-int v1, v9, v10

    invoke-virtual {v11, v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    move-object v1, p0

    :cond_5
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v2

    const-wide/high16 v4, 0x1000000000000000L

    and-long/2addr v2, v4

    cmp-long v2, v2, v6

    if-eqz v2, :cond_7

    invoke-virtual {v1}, Lo/w3;->c()Lo/w3;

    move-result-object v1

    iget-object v2, v1, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    iget v3, v1, Lo/w3;->c:I

    and-int/2addr v3, v9

    invoke-virtual {v2, v3}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    move-result-object v4

    instance-of v5, v4, Lo/v3;

    if-eqz v5, :cond_6

    check-cast v4, Lo/v3;

    iget v4, v4, Lo/v3;->a:I

    if-ne v4, v9, :cond_6

    invoke-virtual {v2, v3, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    goto :goto_1

    :cond_6
    const/4 v1, 0x0

    :goto_1
    if-nez v1, :cond_5

    :cond_7
    const/4 p1, 0x0

    return p1
.end method

.method public final b()Z
    .locals 12

    :cond_0
    sget-object v0, Lo/w3;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v2

    const-wide/high16 v4, 0x2000000000000000L

    and-long v6, v2, v4

    const-wide/16 v8, 0x0

    cmp-long v1, v6, v8

    const/4 v6, 0x1

    if-eqz v1, :cond_1

    return v6

    :cond_1
    const-wide/high16 v10, 0x1000000000000000L

    and-long/2addr v10, v2

    cmp-long v1, v10, v8

    if-eqz v1, :cond_2

    const/4 v0, 0x0

    return v0

    :cond_2
    or-long/2addr v4, v2

    move-object v1, p0

    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v0

    if-eqz v0, :cond_0

    return v6
.end method

.method public final c()Lo/w3;
    .locals 11

    :cond_0
    sget-object v0, Lo/w3;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v2

    const-wide/high16 v4, 0x1000000000000000L

    and-long v6, v2, v4

    const-wide/16 v8, 0x0

    cmp-long v1, v6, v8

    if-eqz v1, :cond_1

    move-object v1, p0

    goto :goto_0

    :cond_1
    or-long/2addr v4, v2

    move-object v1, p0

    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v2

    if-eqz v2, :cond_0

    move-wide v2, v4

    :goto_0
    sget-object v4, Lo/w3;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lo/w3;

    if-eqz v5, :cond_2

    return-object v5

    :cond_2
    new-instance v5, Lo/w3;

    iget v6, v1, Lo/w3;->a:I

    mul-int/lit8 v6, v6, 0x2

    iget-boolean v7, v1, Lo/w3;->b:Z

    invoke-direct {v5, v6, v7}, Lo/w3;-><init>(IZ)V

    const-wide/32 v6, 0x3fffffff

    and-long/2addr v6, v2

    long-to-int v6, v6

    const-wide v7, 0xfffffffc0000000L

    and-long/2addr v7, v2

    const/16 v9, 0x1e

    shr-long/2addr v7, v9

    long-to-int v7, v7

    :goto_1
    iget v8, v1, Lo/w3;->c:I

    and-int v9, v6, v8

    and-int/2addr v8, v7

    if-eq v9, v8, :cond_4

    iget-object v8, v1, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    invoke-virtual {v8, v9}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    move-result-object v8

    if-nez v8, :cond_3

    new-instance v8, Lo/v3;

    invoke-direct {v8, v6}, Lo/v3;-><init>(I)V

    :cond_3
    iget-object v9, v5, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    iget v10, v5, Lo/w3;->c:I

    and-int/2addr v10, v6

    invoke-virtual {v9, v10, v8}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    :cond_4
    const-wide v6, -0x1000000000000001L    # -3.1050361846014175E231

    and-long/2addr v6, v2

    invoke-virtual {v0, v5, v6, v7}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->set(Ljava/lang/Object;J)V

    :cond_5
    const/4 v6, 0x0

    invoke-virtual {v4, p0, v6, v5}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_6

    goto :goto_0

    :cond_6
    invoke-virtual {v4, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    if-eqz v6, :cond_5

    goto :goto_0
.end method

.method public final d()Ljava/lang/Object;
    .locals 30

    move-object/from16 v1, p0

    :cond_0
    sget-object v0, Lo/w3;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v2

    const-wide/high16 v6, 0x1000000000000000L

    and-long v4, v2, v6

    const-wide/16 v8, 0x0

    cmp-long v4, v4, v8

    if-eqz v4, :cond_1

    sget-object v0, Lo/w3;->g:Lo/Q;

    return-object v0

    :cond_1
    const-wide/32 v10, 0x3fffffff

    and-long v4, v2, v10

    long-to-int v4, v4

    const-wide v12, 0xfffffffc0000000L

    and-long/2addr v12, v2

    const/16 v5, 0x1e

    shr-long/2addr v12, v5

    long-to-int v5, v12

    iget v12, v1, Lo/w3;->c:I

    and-int/2addr v5, v12

    and-int/2addr v12, v4

    const/4 v13, 0x0

    if-ne v5, v12, :cond_2

    goto :goto_0

    :cond_2
    iget-object v14, v1, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    invoke-virtual {v14, v12}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    move-result-object v15

    iget-boolean v5, v1, Lo/w3;->b:Z

    if-nez v15, :cond_3

    if-eqz v5, :cond_0

    goto :goto_0

    :cond_3
    move-wide/from16 v16, v6

    instance-of v6, v15, Lo/v3;

    if-eqz v6, :cond_4

    :goto_0
    return-object v13

    :cond_4
    add-int/lit8 v4, v4, 0x1

    const v6, 0x3fffffff    # 1.9999999f

    and-int/2addr v4, v6

    const-wide/32 v6, -0x40000000

    and-long v18, v2, v6

    move-wide/from16 v20, v6

    int-to-long v6, v4

    or-long v18, v18, v6

    move-wide/from16 v28, v18

    move/from16 v18, v5

    move-wide/from16 v4, v28

    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {v14, v12, v13}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    return-object v15

    :cond_5
    move-object/from16 v1, p0

    if-eqz v18, :cond_0

    :cond_6
    sget-object v0, Lo/w3;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    move-result-wide v24

    and-long v2, v24, v10

    long-to-int v2, v2

    and-long v3, v24, v16

    cmp-long v3, v3, v8

    if-eqz v3, :cond_7

    invoke-virtual {v1}, Lo/w3;->c()Lo/w3;

    move-result-object v0

    move-object v1, v0

    goto :goto_1

    :cond_7
    and-long v3, v24, v20

    or-long v26, v3, v6

    move-object/from16 v22, v0

    move-object/from16 v23, v1

    invoke-virtual/range {v22 .. v27}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    move-result v0

    move-object/from16 v1, v23

    if-eqz v0, :cond_6

    iget-object v0, v1, Lo/w3;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    iget v1, v1, Lo/w3;->c:I

    and-int/2addr v1, v2

    invoke-virtual {v0, v1, v13}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    move-object v1, v13

    :goto_1
    if-nez v1, :cond_6

    return-object v15
.end method

.class public abstract Lo/d5;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Ljava/lang/String;

.field public static final b:J

.field public static final c:I

.field public static final d:I

.field public static final e:J

.field public static final f:Lo/D0;

.field public static final g:Lo/b5;

.field public static final h:Lo/b5;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    const-string v0, "kotlinx.coroutines.scheduler.default.name"

    sget v1, Lo/Z4;->a:I

    :try_start_0
    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_0

    const-string v0, "DefaultDispatcher"

    :cond_0
    sput-object v0, Lo/d5;->a:Ljava/lang/String;

    const-wide v5, 0x7fffffffffffffffL

    const-wide/16 v3, 0x1

    const-string v7, "kotlinx.coroutines.scheduler.resolution.ns"

    const-wide/32 v1, 0x186a0

    invoke-static/range {v1 .. v7}, Lo/G4;->l(JJJLjava/lang/String;)J

    move-result-wide v0

    sput-wide v0, Lo/d5;->b:J

    sget v0, Lo/Z4;->a:I

    const/4 v1, 0x2

    if-ge v0, v1, :cond_1

    move v0, v1

    :cond_1
    const/16 v1, 0x8

    const-string v2, "kotlinx.coroutines.scheduler.core.pool.size"

    invoke-static {v2, v0, v1}, Lo/G4;->m(Ljava/lang/String;II)I

    move-result v0

    sput v0, Lo/d5;->c:I

    const-string v0, "kotlinx.coroutines.scheduler.max.pool.size"

    const v1, 0x1ffffe

    const/4 v2, 0x4

    invoke-static {v0, v1, v2}, Lo/G4;->m(Ljava/lang/String;II)I

    move-result v0

    sput v0, Lo/d5;->d:I

    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    const-wide v5, 0x7fffffffffffffffL

    const-wide/16 v3, 0x1

    const-string v7, "kotlinx.coroutines.scheduler.keep.alive.sec"

    const-wide/16 v1, 0x3c

    invoke-static/range {v1 .. v7}, Lo/G4;->l(JJJLjava/lang/String;)J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    sput-wide v0, Lo/d5;->e:J

    sget-object v0, Lo/D0;->d:Lo/D0;

    sput-object v0, Lo/d5;->f:Lo/D0;

    new-instance v0, Lo/b5;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Lo/b5;-><init>(I)V

    sput-object v0, Lo/d5;->g:Lo/b5;

    new-instance v0, Lo/b5;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Lo/b5;-><init>(I)V

    sput-object v0, Lo/d5;->h:Lo/b5;

    return-void
.end method

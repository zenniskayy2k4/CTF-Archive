.class public abstract Lo/P;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/Y2;
.implements Ljava/io/Serializable;


# static fields
.field public static final NO_RECEIVER:Ljava/lang/Object;


# instance fields
.field private final isTopLevel:Z

.field private final name:Ljava/lang/String;

.field private final owner:Ljava/lang/Class;

.field protected final receiver:Ljava/lang/Object;

.field private transient reflected:Lo/Y2;

.field private final signature:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Lo/O;->a:Lo/O;

    sput-object v0, Lo/P;->NO_RECEIVER:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/P;->receiver:Ljava/lang/Object;

    iput-object p2, p0, Lo/P;->owner:Ljava/lang/Class;

    iput-object p3, p0, Lo/P;->name:Ljava/lang/String;

    iput-object p4, p0, Lo/P;->signature:Ljava/lang/String;

    iput-boolean p5, p0, Lo/P;->isTopLevel:Z

    return-void
.end method


# virtual methods
.method public varargs call([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0, p1}, Lo/Y2;->call([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public callBy(Ljava/util/Map;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0, p1}, Lo/Y2;->callBy(Ljava/util/Map;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public compute()Lo/Y2;
    .locals 1

    iget-object v0, p0, Lo/P;->reflected:Lo/Y2;

    if-nez v0, :cond_0

    invoke-virtual {p0}, Lo/P;->computeReflected()Lo/Y2;

    move-result-object v0

    iput-object v0, p0, Lo/P;->reflected:Lo/Y2;

    :cond_0
    return-object v0
.end method

.method public abstract computeReflected()Lo/Y2;
.end method

.method public getAnnotations()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/annotation/Annotation;",
            ">;"
        }
    .end annotation

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/X2;->getAnnotations()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public getBoundReceiver()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Lo/P;->receiver:Ljava/lang/Object;

    return-object v0
.end method

.method public getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Lo/P;->name:Ljava/lang/String;

    return-object v0
.end method

.method public getOwner()Lo/a3;
    .locals 2

    iget-object v0, p0, Lo/P;->owner:Ljava/lang/Class;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    iget-boolean v1, p0, Lo/P;->isTopLevel:Z

    if-eqz v1, :cond_1

    sget-object v1, Lo/l4;->a:Lo/m4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Lo/V3;

    invoke-direct {v1, v0}, Lo/V3;-><init>(Ljava/lang/Class;)V

    return-object v1

    :cond_1
    sget-object v1, Lo/l4;->a:Lo/m4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Lo/d0;

    invoke-direct {v1, v0}, Lo/d0;-><init>(Ljava/lang/Class;)V

    return-object v1
.end method

.method public getParameters()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->getParameters()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public abstract getReflected()Lo/Y2;
.end method

.method public getReturnType()Lo/f3;
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->getReturnType()Lo/f3;

    const/4 v0, 0x0

    return-object v0
.end method

.method public getSignature()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Lo/P;->signature:Ljava/lang/String;

    return-object v0
.end method

.method public getTypeParameters()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->getTypeParameters()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public getVisibility()Lo/g3;
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->getVisibility()Lo/g3;

    move-result-object v0

    return-object v0
.end method

.method public isAbstract()Z
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->isAbstract()Z

    move-result v0

    return v0
.end method

.method public isFinal()Z
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->isFinal()Z

    move-result v0

    return v0
.end method

.method public isOpen()Z
    .locals 1

    invoke-virtual {p0}, Lo/P;->getReflected()Lo/Y2;

    move-result-object v0

    invoke-interface {v0}, Lo/Y2;->isOpen()Z

    move-result v0

    return v0
.end method

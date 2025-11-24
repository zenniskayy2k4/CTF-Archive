.class public final Lo/t2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/u2;


# instance fields
.field public final a:Lo/R3;


# direct methods
.method public constructor <init>(Lo/R3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/t2;->a:Lo/R3;

    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final d()Lo/R3;
    .locals 1

    iget-object v0, p0, Lo/t2;->a:Lo/R3;

    return-object v0
.end method

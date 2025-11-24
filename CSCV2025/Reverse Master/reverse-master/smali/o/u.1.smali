.class public final Lo/u;
.super Lo/d;
.source "SourceFile"

# interfaces
.implements Lo/F0;


# instance fields
.field private volatile _preHandler:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    sget-object v0, Lo/D0;->b:Lo/D0;

    invoke-direct {p0, v0}, Lo/d;-><init>(Lo/G0;)V

    iput-object p0, p0, Lo/u;->_preHandler:Ljava/lang/Object;

    return-void
.end method

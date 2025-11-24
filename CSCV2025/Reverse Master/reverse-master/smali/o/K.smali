.class public final Lo/K;
.super Lo/w1;
.source "SourceFile"


# instance fields
.field public final g:Ljava/lang/Thread;


# direct methods
.method public constructor <init>(Ljava/lang/Thread;)V
    .locals 0

    invoke-direct {p0}, Lo/w1;-><init>()V

    iput-object p1, p0, Lo/K;->g:Ljava/lang/Thread;

    return-void
.end method


# virtual methods
.method public final c()Ljava/lang/Thread;
    .locals 1

    iget-object v0, p0, Lo/K;->g:Ljava/lang/Thread;

    return-object v0
.end method

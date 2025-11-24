.class public final Lo/L2;
.super Lo/S2;
.source "SourceFile"


# instance fields
.field public final e:Lo/E2;


# direct methods
.method public constructor <init>(Lo/E2;)V
    .locals 0

    invoke-direct {p0}, Lo/t3;-><init>()V

    iput-object p1, p0, Lo/L2;->e:Lo/E2;

    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Lo/L2;->e:Lo/E2;

    invoke-interface {v0, p1}, Lo/E2;->c(Ljava/lang/Throwable;)V

    return-void
.end method

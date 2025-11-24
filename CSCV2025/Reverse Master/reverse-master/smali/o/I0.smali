.class public final Lo/I0;
.super Lo/h3;
.source "SourceFile"

# interfaces
.implements Lo/S1;


# static fields
.field public static final a:Lo/I0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Lo/I0;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Lo/h3;-><init>(I)V

    sput-object v0, Lo/I0;->a:Lo/I0;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Lo/F0;

    instance-of v0, p1, Lo/K0;

    if-eqz v0, :cond_0

    check-cast p1, Lo/K0;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

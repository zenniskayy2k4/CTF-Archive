.class public final Lo/t1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/C4;


# static fields
.field public static final a:Lo/t1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lo/t1;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Lo/t1;->a:Lo/t1;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    sget-object v0, Lo/q1;->a:Lo/q1;

    return-object v0
.end method

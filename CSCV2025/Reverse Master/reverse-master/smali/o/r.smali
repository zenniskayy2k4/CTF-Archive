.class public final Lo/r;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lo/T3;


# static fields
.field public static final a:Lo/r;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Lo/r;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Lo/r;->a:Lo/r;

    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Active"

    return-object v0
.end method

.class public final Lo/m0;
.super Lo/h3;
.source "SourceFile"

# interfaces
.implements Lo/W1;


# static fields
.field public static final b:Lo/m0;

.field public static final c:Lo/m0;

.field public static final d:Lo/m0;

.field public static final e:Lo/m0;

.field public static final f:Lo/m0;

.field public static final g:Lo/m0;

.field public static final h:Lo/m0;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->b:Lo/m0;

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->c:Lo/m0;

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x2

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->d:Lo/m0;

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x3

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->e:Lo/m0;

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x4

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->f:Lo/m0;

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x5

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->g:Lo/m0;

    new-instance v0, Lo/m0;

    const/4 v1, 0x2

    const/4 v2, 0x6

    invoke-direct {v0, v1, v2}, Lo/m0;-><init>(II)V

    sput-object v0, Lo/m0;->h:Lo/m0;

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    iput p2, p0, Lo/m0;->a:I

    invoke-direct {p0, p1}, Lo/h3;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Lo/m0;->a:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Lo/H0;

    check-cast p2, Lo/F0;

    invoke-interface {p1, p2}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Lo/h5;

    check-cast p2, Lo/F0;

    return-object p1

    :pswitch_1
    check-cast p1, Lo/e5;

    check-cast p2, Lo/F0;

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of p1, p2, Lo/e5;

    if-eqz p1, :cond_1

    move-object p1, p2

    check-cast p1, Lo/e5;

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    return-object p1

    :pswitch_2
    check-cast p2, Lo/F0;

    instance-of v0, p2, Lo/e5;

    if-eqz v0, :cond_5

    instance-of v0, p1, Ljava/lang/Integer;

    if-eqz v0, :cond_2

    check-cast p1, Ljava/lang/Integer;

    goto :goto_1

    :cond_2
    const/4 p1, 0x0

    :goto_1
    const/4 v0, 0x1

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    goto :goto_2

    :cond_3
    move p1, v0

    :goto_2
    if-nez p1, :cond_4

    move-object p1, p2

    goto :goto_3

    :cond_4
    add-int/2addr p1, v0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    :cond_5
    :goto_3
    return-object p1

    :pswitch_3
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    check-cast p2, Lo/F0;

    return-object p1

    :pswitch_4
    check-cast p1, Lo/H0;

    check-cast p2, Lo/F0;

    invoke-interface {p1, p2}, Lo/H0;->plus(Lo/H0;)Lo/H0;

    move-result-object p1

    return-object p1

    :pswitch_5
    check-cast p1, Lo/H0;

    check-cast p2, Lo/F0;

    const-string v0, "acc"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "element"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p2}, Lo/F0;->getKey()Lo/G0;

    move-result-object v0

    invoke-interface {p1, v0}, Lo/H0;->minusKey(Lo/G0;)Lo/H0;

    move-result-object p1

    sget-object v0, Lo/p1;->a:Lo/p1;

    if-ne p1, v0, :cond_6

    goto :goto_5

    :cond_6
    sget-object v1, Lo/D0;->a:Lo/D0;

    invoke-interface {p1, v1}, Lo/H0;->get(Lo/G0;)Lo/F0;

    move-result-object v2

    check-cast v2, Lo/E0;

    if-nez v2, :cond_7

    new-instance v0, Lo/n0;

    invoke-direct {v0, p1, p2}, Lo/n0;-><init>(Lo/H0;Lo/F0;)V

    :goto_4
    move-object p2, v0

    goto :goto_5

    :cond_7
    invoke-interface {p1, v1}, Lo/H0;->minusKey(Lo/G0;)Lo/H0;

    move-result-object p1

    if-ne p1, v0, :cond_8

    new-instance p1, Lo/n0;

    invoke-direct {p1, p2, v2}, Lo/n0;-><init>(Lo/H0;Lo/F0;)V

    move-object p2, p1

    goto :goto_5

    :cond_8
    new-instance v0, Lo/n0;

    new-instance v1, Lo/n0;

    invoke-direct {v1, p1, p2}, Lo/n0;-><init>(Lo/H0;Lo/F0;)V

    invoke-direct {v0, v1, v2}, Lo/n0;-><init>(Lo/H0;Lo/F0;)V

    goto :goto_4

    :goto_5
    return-object p2

    :pswitch_6
    check-cast p1, Ljava/lang/String;

    check-cast p2, Lo/F0;

    const-string v0, "acc"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "element"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_9

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_6

    :cond_9
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, ", "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    :goto_6
    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

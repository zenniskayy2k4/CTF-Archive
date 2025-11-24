.class public final Lo/p3;
.super Lo/j;
.source "SourceFile"

# interfaces
.implements Ljava/util/RandomAccess;
.implements Ljava/io/Serializable;


# static fields
.field public static final d:Lo/p3;


# instance fields
.field public a:[Ljava/lang/Object;

.field public b:I

.field public c:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Lo/p3;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Lo/p3;-><init>(I)V

    const/4 v1, 0x1

    iput-boolean v1, v0, Lo/p3;->c:Z

    sput-object v0, Lo/p3;->d:Lo/p3;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    invoke-direct {p0}, Ljava/util/AbstractList;-><init>()V

    if-ltz p1, :cond_0

    new-array p1, p1, [Ljava/lang/Object;

    iput-object p1, p0, Lo/p3;->a:[Ljava/lang/Object;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "capacity must be non-negative."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public static final synthetic c(Lo/p3;)I
    .locals 0

    iget p0, p0, Ljava/util/AbstractList;->modCount:I

    return p0
.end method


# virtual methods
.method public final a()I
    .locals 1

    iget v0, p0, Lo/p3;->b:I

    return v0
.end method

.method public final add(ILjava/lang/Object;)V
    .locals 2

    .line 6
    invoke-virtual {p0}, Lo/p3;->f()V

    .line 7
    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->b(II)V

    .line 8
    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    .line 9
    invoke-virtual {p0, p1, v1}, Lo/p3;->g(II)V

    .line 10
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    aput-object p2, v0, p1

    return-void
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Lo/p3;->f()V

    .line 2
    iget v0, p0, Lo/p3;->b:I

    .line 3
    iget v1, p0, Ljava/util/AbstractList;->modCount:I

    const/4 v2, 0x1

    add-int/2addr v1, v2

    iput v1, p0, Ljava/util/AbstractList;->modCount:I

    .line 4
    invoke-virtual {p0, v0, v2}, Lo/p3;->g(II)V

    .line 5
    iget-object v1, p0, Lo/p3;->a:[Ljava/lang/Object;

    aput-object p1, v1, v0

    return v2
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 2

    const-string v0, "elements"

    invoke-static {p2, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-virtual {p0}, Lo/p3;->f()V

    .line 5
    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->b(II)V

    .line 6
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v0

    .line 7
    invoke-virtual {p0, p1, p2, v0}, Lo/p3;->d(ILjava/util/Collection;I)V

    if-lez v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 2

    const-string v0, "elements"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0}, Lo/p3;->f()V

    .line 2
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    .line 3
    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {p0, v1, p1, v0}, Lo/p3;->d(ILjava/util/Collection;I)V

    if-lez v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final b(I)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Lo/p3;->f()V

    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->a(II)V

    invoke-virtual {p0, p1}, Lo/p3;->h(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final clear()V
    .locals 2

    invoke-virtual {p0}, Lo/p3;->f()V

    const/4 v0, 0x0

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {p0, v0, v1}, Lo/p3;->i(II)V

    return-void
.end method

.method public final d(ILjava/util/Collection;I)V
    .locals 4

    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    invoke-virtual {p0, p1, p3}, Lo/p3;->g(II)V

    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p3, :cond_0

    iget-object v1, p0, Lo/p3;->a:[Ljava/lang/Object;

    add-int v2, p1, v0

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    aput-object v3, v1, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final e(ILjava/lang/Object;)V
    .locals 2

    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    invoke-virtual {p0, p1, v1}, Lo/p3;->g(II)V

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    aput-object p2, v0, p1

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    if-eq p1, p0, :cond_1

    instance-of v0, p1, Ljava/util/List;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Ljava/util/List;

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    iget v2, p0, Lo/p3;->b:I

    invoke-static {v0, v1, v2, p1}, Lo/W0;->a([Ljava/lang/Object;IILjava/util/List;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    return v1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final f()V
    .locals 1

    iget-boolean v0, p0, Lo/p3;->c:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw v0
.end method

.method public final g(II)V
    .locals 4

    iget v0, p0, Lo/p3;->b:I

    add-int/2addr v0, p2

    if-ltz v0, :cond_4

    iget-object v1, p0, Lo/p3;->a:[Ljava/lang/Object;

    array-length v2, v1

    if-le v0, v2, :cond_3

    sget-object v2, Lo/i;->Companion:Lo/e;

    array-length v1, v1

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    shr-int/lit8 v2, v1, 0x1

    add-int/2addr v1, v2

    sub-int v2, v1, v0

    if-gez v2, :cond_0

    move v1, v0

    :cond_0
    const v2, 0x7ffffff7

    sub-int v3, v1, v2

    if-lez v3, :cond_2

    if-le v0, v2, :cond_1

    const v1, 0x7fffffff

    goto :goto_0

    :cond_1
    move v1, v2

    :cond_2
    :goto_0
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    const-string v2, "<this>"

    invoke-static {v0, v2}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    const-string v1, "copyOf(...)"

    invoke-static {v0, v1}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    :cond_3
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    iget v1, p0, Lo/p3;->b:I

    add-int v2, p1, p2

    invoke-static {v0, v0, v2, p1, v1}, Lo/H;->x([Ljava/lang/Object;[Ljava/lang/Object;III)V

    iget p1, p0, Lo/p3;->b:I

    add-int/2addr p1, p2

    iput p1, p0, Lo/p3;->b:I

    return-void

    :cond_4
    new-instance p1, Ljava/lang/OutOfMemoryError;

    invoke-direct {p1}, Ljava/lang/OutOfMemoryError;-><init>()V

    throw p1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 2

    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->a(II)V

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    aget-object p1, v0, p1

    return-object p1
.end method

.method public final h(I)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    aget-object v1, v0, p1

    add-int/lit8 v2, p1, 0x1

    iget v3, p0, Lo/p3;->b:I

    invoke-static {v0, v0, p1, v2, v3}, Lo/H;->x([Ljava/lang/Object;[Ljava/lang/Object;III)V

    iget-object p1, p0, Lo/p3;->a:[Ljava/lang/Object;

    iget v0, p0, Lo/p3;->b:I

    add-int/lit8 v0, v0, -0x1

    const-string v2, "<this>"

    invoke-static {p1, v2}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v2, 0x0

    aput-object v2, p1, v0

    iget p1, p0, Lo/p3;->b:I

    add-int/lit8 p1, p1, -0x1

    iput p1, p0, Lo/p3;->b:I

    return-object v1
.end method

.method public final hashCode()I
    .locals 6

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    iget v1, p0, Lo/p3;->b:I

    const/4 v2, 0x1

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v1, :cond_1

    aget-object v5, v0, v4

    mul-int/lit8 v2, v2, 0x1f

    if-eqz v5, :cond_0

    invoke-virtual {v5}, Ljava/lang/Object;->hashCode()I

    move-result v5

    goto :goto_1

    :cond_0
    move v5, v3

    :goto_1
    add-int/2addr v2, v5

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    return v2
.end method

.method public final i(II)V
    .locals 3

    if-lez p2, :cond_0

    iget v0, p0, Ljava/util/AbstractList;->modCount:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Ljava/util/AbstractList;->modCount:I

    :cond_0
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    add-int v1, p1, p2

    iget v2, p0, Lo/p3;->b:I

    invoke-static {v0, v0, p1, v1, v2}, Lo/H;->x([Ljava/lang/Object;[Ljava/lang/Object;III)V

    iget-object p1, p0, Lo/p3;->a:[Ljava/lang/Object;

    iget v0, p0, Lo/p3;->b:I

    sub-int v1, v0, p2

    const-string v2, "<this>"

    invoke-static {p1, v2}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_0
    if-ge v1, v0, :cond_1

    const/4 v2, 0x0

    aput-object v2, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    iget p1, p0, Lo/p3;->b:I

    sub-int/2addr p1, p2

    iput p1, p0, Lo/p3;->b:I

    return-void
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 2

    const/4 v0, 0x0

    :goto_0
    iget v1, p0, Lo/p3;->b:I

    if-ge v0, v1, :cond_1

    iget-object v1, p0, Lo/p3;->a:[Ljava/lang/Object;

    aget-object v1, v1, v0

    invoke-static {v1, p1}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    return v0

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    const/4 p1, -0x1

    return p1
.end method

.method public final isEmpty()Z
    .locals 1

    iget v0, p0, Lo/p3;->b:I

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Lo/p3;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v0

    return-object v0
.end method

.method public final j(IILjava/util/Collection;Z)I
    .locals 5

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    if-ge v0, p2, :cond_1

    iget-object v2, p0, Lo/p3;->a:[Ljava/lang/Object;

    add-int v3, p1, v0

    aget-object v2, v2, v3

    invoke-interface {p3, v2}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-ne v2, p4, :cond_0

    iget-object v2, p0, Lo/p3;->a:[Ljava/lang/Object;

    add-int/lit8 v4, v1, 0x1

    add-int/2addr v1, p1

    add-int/lit8 v0, v0, 0x1

    aget-object v3, v2, v3

    aput-object v3, v2, v1

    move v1, v4

    goto :goto_0

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    sub-int p3, p2, v1

    iget-object p4, p0, Lo/p3;->a:[Ljava/lang/Object;

    add-int/2addr p2, p1

    iget v0, p0, Lo/p3;->b:I

    add-int/2addr p1, v1

    invoke-static {p4, p4, p1, p2, v0}, Lo/H;->x([Ljava/lang/Object;[Ljava/lang/Object;III)V

    iget-object p1, p0, Lo/p3;->a:[Ljava/lang/Object;

    iget p2, p0, Lo/p3;->b:I

    sub-int p4, p2, p3

    const-string v0, "<this>"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_1
    if-ge p4, p2, :cond_2

    const/4 v0, 0x0

    aput-object v0, p1, p4

    add-int/lit8 p4, p4, 0x1

    goto :goto_1

    :cond_2
    if-lez p3, :cond_3

    iget p1, p0, Ljava/util/AbstractList;->modCount:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Ljava/util/AbstractList;->modCount:I

    :cond_3
    iget p1, p0, Lo/p3;->b:I

    sub-int/2addr p1, p3

    iput p1, p0, Lo/p3;->b:I

    return p3
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 2

    iget v0, p0, Lo/p3;->b:I

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-ltz v0, :cond_1

    iget-object v1, p0, Lo/p3;->a:[Ljava/lang/Object;

    aget-object v1, v1, v0

    invoke-static {v1, p1}, Lo/F2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    return v0

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    const/4 p1, -0x1

    return p1
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, v0}, Lo/p3;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v0

    return-object v0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 2

    .line 2
    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->b(II)V

    .line 3
    new-instance v0, Lo/n3;

    invoke-direct {v0, p0, p1}, Lo/n3;-><init>(Lo/p3;I)V

    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 0

    invoke-virtual {p0}, Lo/p3;->f()V

    invoke-virtual {p0, p1}, Lo/p3;->indexOf(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    invoke-virtual {p0, p1}, Lo/p3;->b(I)Ljava/lang/Object;

    :cond_0
    if-ltz p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 2

    const-string v0, "elements"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Lo/p3;->f()V

    iget v0, p0, Lo/p3;->b:I

    const/4 v1, 0x0

    invoke-virtual {p0, v1, v0, p1, v1}, Lo/p3;->j(IILjava/util/Collection;Z)I

    move-result p1

    if-lez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    return v1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 3

    const-string v0, "elements"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Lo/p3;->f()V

    iget v0, p0, Lo/p3;->b:I

    const/4 v1, 0x0

    const/4 v2, 0x1

    invoke-virtual {p0, v1, v0, p1, v2}, Lo/p3;->j(IILjava/util/Collection;Z)I

    move-result p1

    if-lez p1, :cond_0

    return v2

    :cond_0
    return v1
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Lo/p3;->f()V

    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, v1}, Lo/e;->a(II)V

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    aget-object v1, v0, p1

    aput-object p2, v0, p1

    return-object v1
.end method

.method public final subList(II)Ljava/util/List;
    .locals 8

    sget-object v0, Lo/i;->Companion:Lo/e;

    iget v1, p0, Lo/p3;->b:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, p2, v1}, Lo/e;->c(III)V

    new-instance v2, Lo/o3;

    iget-object v3, p0, Lo/p3;->a:[Ljava/lang/Object;

    sub-int v5, p2, p1

    const/4 v6, 0x0

    move-object v7, p0

    move v4, p1

    invoke-direct/range {v2 .. v7}, Lo/o3;-><init>([Ljava/lang/Object;IILo/o3;Lo/p3;)V

    return-object v2
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 3

    .line 7
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    const/4 v1, 0x0

    iget v2, p0, Lo/p3;->b:I

    invoke-static {v0, v1, v2}, Lo/H;->A([Ljava/lang/Object;II)[Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 3

    const-string v0, "array"

    invoke-static {p1, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    array-length v0, p1

    iget v1, p0, Lo/p3;->b:I

    const/4 v2, 0x0

    if-ge v0, v1, :cond_0

    .line 2
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-static {v0, v2, v1, p1}, Ljava/util/Arrays;->copyOfRange([Ljava/lang/Object;IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object p1

    const-string v0, "copyOfRange(...)"

    invoke-static {p1, v0}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    .line 3
    :cond_0
    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    invoke-static {v0, p1, v2, v2, v1}, Lo/H;->x([Ljava/lang/Object;[Ljava/lang/Object;III)V

    .line 4
    iget v0, p0, Lo/p3;->b:I

    .line 5
    array-length v1, p1

    if-ge v0, v1, :cond_1

    const/4 v1, 0x0

    .line 6
    aput-object v1, p1, v0

    :cond_1
    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Lo/p3;->a:[Ljava/lang/Object;

    const/4 v1, 0x0

    iget v2, p0, Lo/p3;->b:I

    invoke-static {v0, v1, v2, p0}, Lo/W0;->b([Ljava/lang/Object;IILo/j;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

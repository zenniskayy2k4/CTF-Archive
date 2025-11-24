.class public abstract Lo/V4;
.super Lo/U4;
.source "SourceFile"


# direct methods
.method public static u(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 1

    const/4 v0, 0x0

    invoke-static {p0, p1, v0, v0}, Lo/V4;->v(Ljava/lang/String;Ljava/lang/String;IZ)I

    move-result p0

    if-ltz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    return v0
.end method

.method public static final v(Ljava/lang/String;Ljava/lang/String;IZ)I
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p3, :cond_0

    invoke-virtual {p0, p1, p2}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    move-result p0

    return p0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    new-instance v1, Lo/z2;

    if-gez p2, :cond_1

    const/4 p2, 0x0

    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    if-le v0, v2, :cond_2

    move v0, v2

    :cond_2
    const/4 v2, 0x1

    invoke-direct {v1, p2, v0, v2}, Lo/x2;-><init>(III)V

    iget v0, v1, Lo/x2;->b:I

    if-le p2, v0, :cond_3

    goto :goto_2

    :cond_3
    move v5, p2

    :goto_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v6

    const/4 v3, 0x0

    if-nez p3, :cond_4

    invoke-virtual {p1, v3, p0, v5, v6}, Ljava/lang/String;->regionMatches(ILjava/lang/String;II)Z

    move-result p2

    move-object v4, p0

    move-object v1, p1

    move v2, p3

    goto :goto_1

    :cond_4
    move-object v4, p0

    move-object v1, p1

    move v2, p3

    invoke-virtual/range {v1 .. v6}, Ljava/lang/String;->regionMatches(ZILjava/lang/String;II)Z

    move-result p2

    :goto_1
    if-eqz p2, :cond_5

    return v5

    :cond_5
    if-eq v5, v0, :cond_6

    add-int/lit8 v5, v5, 0x1

    move-object p1, v1

    move p3, v2

    move-object p0, v4

    goto :goto_0

    :cond_6
    :goto_2
    const/4 p0, -0x1

    return p0
.end method

.method public static w(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "missingDelimiterValue"

    invoke-static {p0, v0}, Lo/F2;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    const/16 v1, 0x2e

    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->lastIndexOf(II)I

    move-result v0

    const/4 v1, -0x1

    if-ne v0, v1, :cond_0

    return-object p0

    :cond_0
    add-int/lit8 v0, v0, 0x1

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v1

    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p0

    const-string v0, "substring(...)"

    invoke-static {p0, v0}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

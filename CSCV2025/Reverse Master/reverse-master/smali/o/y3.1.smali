.class public final synthetic Lo/y3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic a:Lcom/google/android/material/textfield/TextInputEditText;

.field public final synthetic b:Lcom/ctf/challenge/MainActivity;

.field public final synthetic c:Lcom/google/android/material/textfield/TextInputLayout;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/textfield/TextInputEditText;Lcom/ctf/challenge/MainActivity;Lcom/google/android/material/textfield/TextInputLayout;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo/y3;->a:Lcom/google/android/material/textfield/TextInputEditText;

    iput-object p2, p0, Lo/y3;->b:Lcom/ctf/challenge/MainActivity;

    iput-object p3, p0, Lo/y3;->c:Lcom/google/android/material/textfield/TextInputLayout;

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 12

    const/16 p1, 0x10

    const/4 v0, 0x1

    sget v1, Lcom/ctf/challenge/MainActivity;->b:I

    iget-object v1, p0, Lo/y3;->a:Lcom/google/android/material/textfield/TextInputEditText;

    invoke-virtual {v1}, Landroidx/appcompat/widget/AppCompatEditText;->getText()Landroid/text/Editable;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lo/y3;->b:Lcom/ctf/challenge/MainActivity;

    const-string v3, "CSCV2025{"

    invoke-virtual {v1, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v3

    const/4 v4, 0x0

    if-nez v3, :cond_0

    :goto_0
    move p1, v4

    goto :goto_2

    :cond_0
    const-string v3, "}"

    invoke-virtual {v1, v3}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v3

    sub-int/2addr v3, v0

    const/16 v5, 0x9

    invoke-virtual {v1, v5, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v1

    const-string v3, "substring(...)"

    invoke-static {v1, v3}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v4, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v5

    invoke-static {v5, v3}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    new-array v6, p1, [B

    fill-array-data v6, :array_0

    new-array v7, p1, [B

    move v8, v4

    :goto_1
    if-ge v8, p1, :cond_2

    aget-byte v9, v6, v8

    iget-object v10, v2, Lcom/ctf/challenge/MainActivity;->a:[B

    array-length v11, v10

    rem-int v11, v8, v11

    aget-byte v10, v10, v11

    xor-int/2addr v9, v10

    int-to-byte v9, v9

    aput-byte v9, v7, v8

    add-int/2addr v8, v0

    goto :goto_1

    :cond_2
    new-instance v6, Ljava/lang/String;

    sget-object v8, Lo/X;->a:Ljava/nio/charset/Charset;

    invoke-direct {v6, v7, v8}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    invoke-virtual {v5, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_0

    :cond_3
    invoke-virtual {v1, p1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Lo/F2;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Lcom/ctf/challenge/MainActivity;->checkSecondHalf(Ljava/lang/String;)Z

    move-result p1

    :goto_2
    iget-object v1, p0, Lo/y3;->c:Lcom/google/android/material/textfield/TextInputLayout;

    if-eqz p1, :cond_4

    const-string p1, "\ud83c\udf89 Correct! Flag is valid!"

    invoke-static {v2, p1, v0}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    const/4 p1, 0x0

    invoke-virtual {v1, p1}, Lcom/google/android/material/textfield/TextInputLayout;->setError(Ljava/lang/CharSequence;)V

    return-void

    :cond_4
    const-string p1, "\u274c Wrong flag! Try again!"

    invoke-static {v2, p1, v4}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    const-string p1, "Invalid flag"

    invoke-virtual {v1, p1}, Lcom/google/android/material/textfield/TextInputLayout;->setError(Ljava/lang/CharSequence;)V

    return-void

    nop

    :array_0
    .array-data 1
        0x7at
        0x56t
        0x1bt
        0x16t
        0x35t
        0x23t
        0x50t
        0x4dt
        0x18t
        0x62t
        0x7at
        0x7t
        0x48t
        0x15t
        0x62t
        0x72t
    .end array-data
.end method

.class public final synthetic Lo/F3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;)V
    .locals 0

    iput p1, p0, Lo/F3;->a:I

    iput-object p2, p0, Lo/F3;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 2

    iget-object v0, p0, Lo/F3;->b:Ljava/lang/Object;

    iget v1, p0, Lo/F3;->a:I

    packed-switch v1, :pswitch_data_0

    sget p1, Lcom/ctf/challenge/MainActivity;->b:I

    check-cast v0, Lcom/ctf/challenge/MainActivity;

    invoke-virtual {v0}, Lcom/ctf/challenge/MainActivity;->getHint()Ljava/lang/String;

    move-result-object p1

    const/4 v1, 0x1

    invoke-static {v0, p1, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    return-void

    :pswitch_0
    check-cast v0, Lcom/google/android/material/datepicker/MaterialDatePicker;

    invoke-virtual {v0, p1}, Lcom/google/android/material/datepicker/MaterialDatePicker;->onNegativeButtonClick(Landroid/view/View;)V

    return-void

    :pswitch_1
    check-cast v0, Lcom/google/android/material/datepicker/MaterialDatePicker;

    invoke-virtual {v0, p1}, Lcom/google/android/material/datepicker/MaterialDatePicker;->onPositiveButtonClick(Landroid/view/View;)V

    return-void

    :pswitch_2
    check-cast v0, Lcom/google/android/material/datepicker/MaterialDatePicker;

    invoke-static {v0, p1}, Lcom/google/android/material/datepicker/MaterialDatePicker;->a(Lcom/google/android/material/datepicker/MaterialDatePicker;Landroid/view/View;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

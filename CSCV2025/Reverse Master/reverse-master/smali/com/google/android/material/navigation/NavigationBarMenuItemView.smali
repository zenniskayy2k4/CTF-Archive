.class public interface abstract Lcom/google/android/material/navigation/NavigationBarMenuItemView;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/MenuView$ItemView;


# annotations
.annotation build Landroidx/annotation/RestrictTo;
    value = {
        .enum Landroidx/annotation/RestrictTo$Scope;->LIBRARY_GROUP:Landroidx/annotation/RestrictTo$Scope;
    }
.end annotation


# virtual methods
.method public abstract isExpanded()Z
.end method

.method public abstract isOnlyVisibleWhenExpanded()Z
.end method

.method public abstract setExpanded(Z)V
.end method

.method public abstract setOnlyShowWhenExpanded(Z)V
.end method

package com.lake.ctf;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    long wow = 0;

    public native long Init();

    public native boolean Test(String str);

    static {
        System.loadLibrary("ohgreat2");
    }

    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.wow = Init();
        LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setOrientation(1);
        final TextView textView = new TextView(this);
        textView.setText("this UI follows swiss style");
        final EditText editText = new EditText(this);
        editText.setHint("Enter flag:");
        Button button = new Button(this);
        button.setText("Check flag");
        button.setOnClickListener(new View.OnClickListener() { // from class: com.lake.ctf.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.m4lambda$onCreate$0$comlakectfMainActivity(editText, textView, view);
            }
        });
        linearLayout.addView(editText);
        linearLayout.addView(button);
        linearLayout.addView(textView);
        setContentView(linearLayout);
    }

    /* renamed from: lambda$onCreate$0$com-lake-ctf-MainActivity, reason: not valid java name */
    /* synthetic */ void m4lambda$onCreate$0$comlakectfMainActivity(EditText editText, TextView textView, View view) {
        String string = editText.getText().toString();
        Log.i("LAKECTF", "flag: " + string);
        if (string.length() != 55) {
            textView.setText("flag is wrong...");
            return;
        }
        boolean zTest = Test(string);
        boolean zTest2 = Test(string);
        boolean zTest3 = Test(string);
        boolean zTest4 = Test(string);
        boolean zTest5 = Test(string);
        boolean zTest6 = Test(string);
        boolean zTest7 = Test(string);
        boolean zTest8 = Test(string);
        boolean zTest9 = Test(string);
        boolean zTest10 = Test(string);
        boolean zTest11 = Test(string);
        boolean zTest12 = Test(string);
        boolean zTest13 = Test(string);
        boolean zTest14 = Test(string);
        boolean zTest15 = Test(string);
        boolean zTest16 = Test(string);
        boolean zTest17 = Test(string);
        boolean zTest18 = Test(string);
        boolean zTest19 = Test(string);
        boolean zTest20 = Test(string);
        boolean zTest21 = Test(string);
        boolean zTest22 = Test(string);
        boolean zTest23 = Test(string);
        boolean zTest24 = Test(string);
        boolean zTest25 = Test(string);
        boolean zTest26 = Test(string);
        boolean zTest27 = Test(string);
        boolean zTest28 = Test(string);
        boolean zTest29 = Test(string);
        boolean zTest30 = Test(string);
        boolean zTest31 = Test(string);
        boolean zTest32 = Test(string);
        boolean zTest33 = Test(string);
        boolean zTest34 = Test(string);
        boolean zTest35 = Test(string);
        boolean zTest36 = Test(string);
        boolean zTest37 = Test(string);
        boolean zTest38 = Test(string);
        boolean zTest39 = Test(string);
        boolean zTest40 = Test(string);
        boolean zTest41 = Test(string);
        boolean zTest42 = Test(string);
        boolean zTest43 = Test(string);
        boolean zTest44 = Test(string);
        boolean zTest45 = Test(string);
        boolean zTest46 = Test(string);
        boolean zTest47 = Test(string);
        boolean zTest48 = Test(string);
        boolean zTest49 = Test(string);
        boolean zTest50 = Test(string);
        boolean zTest51 = Test(string);
        boolean zTest52 = Test(string);
        boolean zTest53 = Test(string);
        boolean zTest54 = Test(string);
        boolean zTest55 = Test(string);
        boolean zTest56 = Test(string);
        boolean zTest57 = Test(string);
        boolean zTest58 = Test(string);
        boolean zTest59 = Test(string);
        boolean zTest60 = Test(string);
        boolean zTest61 = Test(string);
        boolean zTest62 = Test(string);
        boolean zTest63 = Test(string);
        boolean zTest64 = Test(string);
        boolean zTest65 = Test(string);
        boolean zTest66 = Test(string);
        boolean zTest67 = Test(string);
        boolean zTest68 = Test(string);
        boolean zTest69 = Test(string);
        boolean zTest70 = Test(string);
        boolean zTest71 = Test(string);
        boolean zTest72 = Test(string);
        boolean zTest73 = Test(string);
        boolean zTest74 = Test(string);
        boolean zTest75 = Test(string);
        boolean zTest76 = Test(string);
        boolean zTest77 = Test(string);
        boolean zTest78 = Test(string);
        boolean zTest79 = Test(string);
        boolean zTest80 = Test(string);
        if (zTest && zTest2 && zTest3 && zTest4 && zTest5 && zTest6 && zTest7 && zTest8 && zTest9 && zTest10 && zTest11 && zTest12 && zTest13 && zTest14 && zTest15 && zTest16 && zTest17 && zTest18 && zTest19 && zTest20 && zTest21 && zTest22 && zTest23 && zTest24 && zTest25 && zTest26 && zTest27 && zTest28 && zTest29 && zTest30 && zTest31 && zTest32 && zTest33 && zTest34 && zTest35 && zTest36 && zTest37 && zTest38 && zTest39 && zTest40 && zTest41 && zTest42 && zTest43 && zTest44 && zTest45 && zTest46 && zTest47 && zTest48 && zTest49 && zTest50 && zTest51 && zTest52 && zTest53 && zTest54 && zTest55 && zTest56 && zTest57 && zTest58 && zTest59 && zTest60 && zTest61 && zTest62 && zTest63 && zTest64 && zTest65 && zTest66 && zTest67 && zTest68 && zTest69 && zTest70 && zTest71 && zTest72 && zTest73 && zTest74 && zTest75 && zTest76 && zTest77 && zTest78 && zTest79 && zTest80) {
            textView.setText("flag correct!");
        } else {
            textView.setText("flag is wrong...");
        }
    }
}

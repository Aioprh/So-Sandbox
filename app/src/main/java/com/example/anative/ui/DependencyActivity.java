package com.example.anative.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.SoDependency;
import com.google.android.material.appbar.MaterialToolbar;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SO 依赖关系：DT_NEEDED、导出/导入符号，一次看全。
 */
public class DependencyActivity extends AppCompatActivity {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    private TextView tvContent;
    private ProgressBar progress;
    private View scroll;
    private View bottomBar;
    private SoDependency.Info info;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dependency);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        tvContent = findViewById(R.id.tv_content);
        progress = findViewById(R.id.progress);
        scroll = findViewById(R.id.scroll);
        bottomBar = findViewById(R.id.bottom_bar);

        findViewById(R.id.btn_copy).setOnClickListener(v -> {
            if (info == null) return;
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("so-dep", SoDependency.format(info)));
            Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
        });

        findViewById(R.id.btn_export_dot).setOnClickListener(v -> exportDot());

        load();
    }

    private void load() {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) {
            progress.setVisibility(View.GONE);
            tvContent.setText("尚未加载 SO 文件");
            scroll.setVisibility(View.VISIBLE);
            return;
        }

        executor.execute(() -> {
            SoDependency.Info parsed = null;
            String error = null;
            try {
                parsed = SoDependency.parse(soPath);
            } catch (Exception e) {
                error = e.getMessage();
            }

            final SoDependency.Info finalInfo = parsed;
            final String finalError = error;
            handler.post(() -> {
                progress.setVisibility(View.GONE);
                scroll.setVisibility(View.VISIBLE);
                if (finalError != null) {
                    tvContent.setText("解析失败: " + finalError);
                    return;
                }
                info = finalInfo;
                tvContent.setText(SoDependency.format(info));
                bottomBar.setVisibility(View.VISIBLE);
            });
        });
    }

    private void exportDot() {
        if (info == null) return;
        try {
            File dir = new File(android.os.Environment.getExternalStorageDirectory(), "SoSandbox");
            if (!dir.exists() && !dir.mkdirs()) {
                Toast.makeText(this, "无法创建目录", Toast.LENGTH_LONG).show();
                return;
            }
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
                    .format(new java.util.Date());
            File out = new File(dir, "deps_" + stamp + ".dot");
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(SoDependency.toDot(info).getBytes("UTF-8"));
            }
            Toast.makeText(this, "已导出：" + out.getAbsolutePath(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "导出失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}

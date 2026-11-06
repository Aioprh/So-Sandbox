package com.example.anative.ui;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.anative.FileUtils;
import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.FunctionFingerprint;
import com.example.anative.core.NativeFunction;
import com.google.android.material.appbar.MaterialToolbar;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 跨库查重：找出被两个 SO 共用的函数体。
 *
 * <p>典型场景是判断某个 SDK 是不是从别的库抄的，或者确认两个包里的
 * "同名库" 是否真的是同一份编译产物。
 */
public class CloneActivity extends AppCompatActivity {

    private static final int REQUEST_PICK = 1001;
    private static final double THRESHOLD = 0.75;
    private static final int MAX_MATCHES = 200;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    private TextView tvTarget;
    private TextView tvResult;
    private ProgressBar progress;
    private Button btnRun;

    private String targetPath;
    private String targetName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_clone);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        tvTarget = findViewById(R.id.tv_target);
        tvResult = findViewById(R.id.tv_result);
        progress = findViewById(R.id.progress);
        btnRun = findViewById(R.id.btn_run);

        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath != null) {
            tvResult.setText("当前库: " + new File(soPath).getName() + "\n请选择要比对的另一个 SO。");
        } else {
            tvResult.setText("尚未加载 SO 文件");
        }

        findViewById(R.id.btn_pick).setOnClickListener(v -> pickFile());
        btnRun.setOnClickListener(v -> runCompare());
    }

    private void pickFile() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        try {
            startActivityForResult(intent, REQUEST_PICK);
        } catch (Exception e) {
            Toast.makeText(this, "没有可用的文件选择器", Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_PICK || resultCode != RESULT_OK || data == null) return;

        Uri uri = data.getData();
        if (uri == null) return;

        String path = FileUtils.copyToCache(this, uri);
        if (path == null) {
            Toast.makeText(this, "无法读取该文件", Toast.LENGTH_LONG).show();
            return;
        }
        targetPath = path;
        targetName = new File(path).getName();
        int underscore = targetName.indexOf('_');
        if (underscore > 0 && underscore + 1 < targetName.length()) {
            // copyToCache 会加时间戳前缀，展示时去掉
            String stripped = targetName.substring(underscore + 1);
            if (stripped.toLowerCase(Locale.US).endsWith(".so")) targetName = stripped;
        }
        tvTarget.setText("对比目标: " + targetName);
        btnRun.setEnabled(true);
    }

    private void runCompare() {
        String soPath = DataHolder.getInstance().getSoPath();
        List<NativeFunction> currentFunctions = DataHolder.getInstance().getFunctions();
        if (soPath == null || currentFunctions == null || currentFunctions.isEmpty()) {
            Toast.makeText(this, "当前库还没有加载完成", Toast.LENGTH_SHORT).show();
            return;
        }
        if (targetPath == null) {
            Toast.makeText(this, "请先选择对比库", Toast.LENGTH_SHORT).show();
            return;
        }

        btnRun.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        progress.setProgress(10);
        tvResult.setText("正在建立指纹...");

        final String fSoPath = soPath;
        final String fTargetPath = targetPath;

        executor.execute(() -> {
            try {
                List<FunctionFingerprint.Entry> left =
                        FunctionFingerprint.build(fSoPath, currentFunctions);

                handler.post(() -> {
                    progress.setProgress(45);
                    tvResult.setText(String.format(Locale.US,
                            "当前库 %d 个函数已建指纹，正在解析对比库...", left.size()));
                });

                List<NativeFunction> targetFunctions =
                        ElfParser.parseFunctions(fTargetPath, "balanced");
                List<FunctionFingerprint.Entry> right =
                        FunctionFingerprint.build(fTargetPath, targetFunctions);

                handler.post(() -> {
                    progress.setProgress(80);
                    tvResult.setText(String.format(Locale.US,
                            "对比库 %d 个函数已建指纹，正在比对...", right.size()));
                });

                List<FunctionFingerprint.Match> matches =
                        FunctionFingerprint.compare(left, right, THRESHOLD, MAX_MATCHES);

                handler.post(() -> {
                    progress.setVisibility(View.GONE);
                    btnRun.setEnabled(true);
                    tvResult.setText(render(left.size(), right.size(), matches));
                });
            } catch (Exception e) {
                handler.post(() -> {
                    progress.setVisibility(View.GONE);
                    btnRun.setEnabled(true);
                    tvResult.setText("比对失败: " + e.getMessage());
                });
            }
        });
    }

    private String render(int leftCount, int rightCount,
                          List<FunctionFingerprint.Match> matches) {
        StringBuilder sb = new StringBuilder();
        sb.append("当前库: ").append(leftCount).append(" 个函数\n");
        sb.append("对比库: ").append(rightCount).append(" 个函数\n");
        sb.append("阈值: ").append((int) (THRESHOLD * 100)).append("%\n\n");

        if (matches.isEmpty()) {
            sb.append("没有发现相似度达到阈值的函数。\n\n");
            sb.append("这通常意味着两个库是各自独立编译的——\n");
            sb.append("同一份源码换编译器/优化级别后，机器码就不一样了。");
            return sb.toString();
        }

        int high = 0;
        for (FunctionFingerprint.Match m : matches) {
            if (m.similarity >= 0.95) high++;
        }

        sb.append("发现 ").append(matches.size()).append(" 对相似函数");
        if (high > 0) {
            sb.append("（其中 ").append(high).append(" 对几乎完全一致）");
        }
        sb.append("\n\n");

        for (FunctionFingerprint.Match m : matches) {
            sb.append(String.format(Locale.US, "%5.1f%%  ", m.similarity * 100));
            sb.append(shortName(m.left.function.getDemangledName()));
            sb.append("  ↔  ");
            sb.append(shortName(m.right.function.getDemangledName()));
            sb.append('\n');
            sb.append(String.format(Locale.US, "        0x%X (%d B)  ↔  0x%X (%d B)\n",
                    m.left.function.getOffset(), m.left.function.getSize(),
                    m.right.function.getOffset(), m.right.function.getSize()));
        }
        return sb.toString();
    }

    private String shortName(String name) {
        if (name == null) return "?";
        return name.length() > 44 ? name.substring(0, 44) + "…" : name;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
        // 清掉临时拷贝，避免 cache 目录堆积
        if (targetPath != null) {
            try {
                new File(targetPath).delete();
            } catch (Exception ignored) {
            }
        }
    }
}

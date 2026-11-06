package com.example.anative.ui;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.SoDiff;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * SO 版本对比界面。
 *
 * <p>用系统文件选择器挑两个 .so，复制到应用缓存后交给 {@link SoDiff} 分析，
 * 结果按"变更 / 新增 / 删除"分组展示，并支持导出 Markdown 报告。
 */
public class SoDiffActivity extends AppCompatActivity {

    private static final int REQ_OLD = 1001;
    private static final int REQ_NEW = 1002;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final List<SoDiff.FunctionChange> rows = new ArrayList<>();

    private TextView tvOld;
    private TextView tvNew;
    private TextView tvSummary;
    private View rowActions;
    private MaterialButton btnCompare;

    private String oldPath;
    private String newPath;
    private SoDiff.Result result;
    private Adapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_so_diff);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        tvOld = findViewById(R.id.tv_old);
        tvNew = findViewById(R.id.tv_new);
        tvSummary = findViewById(R.id.tv_summary);
        rowActions = findViewById(R.id.row_actions);
        btnCompare = findViewById(R.id.btn_compare);

        findViewById(R.id.btn_pick_old).setOnClickListener(v -> pick(REQ_OLD));
        findViewById(R.id.btn_pick_new).setOnClickListener(v -> pick(REQ_NEW));
        findViewById(R.id.btn_export).setOnClickListener(v -> exportMarkdown());
        btnCompare.setOnClickListener(v -> startCompare());

        RecyclerView recycler = findViewById(R.id.recycler_diff);
        recycler.setLayoutManager(new LinearLayoutManager(this));
        adapter = new Adapter();
        recycler.setAdapter(adapter);
    }

    private void pick(int req) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        try {
            startActivityForResult(intent, req);
        } catch (Exception e) {
            Toast.makeText(this, "无法打开文件选择器", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;

        Uri uri = data.getData();
        String name = queryName(uri);
        File dst = new File(getCacheDir(), "diff/" + (requestCode == REQ_OLD ? "old_" : "new_") + name);
        try {
            copyToFile(uri, dst);
        } catch (Exception e) {
            Toast.makeText(this, "复制文件失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }

        if (requestCode == REQ_OLD) {
            oldPath = dst.getAbsolutePath();
            tvOld.setText("旧版本：" + name);
        } else {
            newPath = dst.getAbsolutePath();
            tvNew.setText("新版本：" + name);
        }
    }

    private void startCompare() {
        if (oldPath == null || newPath == null) {
            Toast.makeText(this, "请先选择两个 SO 文件", Toast.LENGTH_SHORT).show();
            return;
        }
        btnCompare.setEnabled(false);
        btnCompare.setText("正在对比…");
        tvSummary.setText("正在解析函数表并比对，文件较大时需要十几秒。");

        new Thread(() -> {
            SoDiff.Result r = null;
            String error = null;
            try {
                r = SoDiff.compare(oldPath, newPath);
            } catch (Exception e) {
                error = e.getMessage();
            }
            final SoDiff.Result fr = r;
            final String fe = error;
            main.post(() -> {
                btnCompare.setEnabled(true);
                btnCompare.setText("开始对比");
                if (fe != null || fr == null) {
                    tvSummary.setText("对比失败：" + fe);
                    return;
                }
                result = fr;
                render(fr);
            });
        }, "so-diff").start();
    }

    private void render(SoDiff.Result r) {
        StringBuilder sb = new StringBuilder();
        sb.append(r.summaryLine()).append('\n');
        sb.append("旧文件架构：").append(r.oldArch).append('\n');
        sb.append("新文件架构：").append(r.newArch);
        if (!r.oldArch.equals(r.newArch)) {
            sb.append("\n注意：两个文件架构不同，函数级对比结果仅作参考。");
        }
        tvSummary.setText(sb.toString());

        rows.clear();
        rows.addAll(r.changed);
        rows.addAll(r.added);
        rows.addAll(r.removed);
        adapter.notifyDataSetChanged();
        rowActions.setVisibility(rows.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private void exportMarkdown() {
        if (result == null) return;
        try {
            File dir = new File(android.os.Environment.getExternalStorageDirectory(), "SoSandbox");
            if (!dir.exists() && !dir.mkdirs()) {
                Toast.makeText(this, "无法创建目录 " + dir, Toast.LENGTH_LONG).show();
                return;
            }
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
                    .format(new java.util.Date());
            File out = new File(dir, "diff_" + stamp + ".md");
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(result.toMarkdown(200).getBytes("UTF-8"));
            }
            Toast.makeText(this, "已导出：" + out.getAbsolutePath(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "导出失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    // ------------------------------------------------------------------

    private String queryName(Uri uri) {
        String name = null;
        try (android.database.Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) name = c.getString(idx);
            }
        } catch (Exception ignored) {
        }
        if (name == null) name = "lib_" + System.currentTimeMillis() + ".so";
        return name.replace('/', '_');
    }

    private void copyToFile(Uri uri, File dst) throws Exception {
        File parent = dst.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new java.io.IOException("无法创建缓存目录");
        }
        try (InputStream in = getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(dst)) {
            if (in == null) throw new java.io.IOException("无法读取文件");
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }

    // ------------------------------------------------------------------

    private class Adapter extends RecyclerView.Adapter<Adapter.VH> {

        class VH extends RecyclerView.ViewHolder {
            TextView name;
            TextView badge;
            TextView detail;

            VH(@NonNull View itemView) {
                super(itemView);
                name = itemView.findViewById(R.id.tv_name);
                badge = itemView.findViewById(R.id.tv_badge);
                detail = itemView.findViewById(R.id.tv_detail);
            }
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new VH(LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_diff, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int position) {
            SoDiff.FunctionChange c = rows.get(position);
            h.name.setText(c.name);

            switch (c.kind) {
                case SoDiff.KIND_ADDED:
                    h.badge.setText("新增");
                    h.badge.setTextColor(getColor(R.color.green_success));
                    h.detail.setText(String.format(Locale.US, "大小 %d 字节   偏移 0x%X",
                            c.newSize, c.newOffset));
                    break;
                case SoDiff.KIND_REMOVED:
                    h.badge.setText("删除");
                    h.badge.setTextColor(getColor(R.color.red_error));
                    h.detail.setText(String.format(Locale.US, "大小 %d 字节   偏移 0x%X",
                            c.oldSize, c.oldOffset));
                    break;
                default:
                    h.badge.setText(c.similarity + "%");
                    h.badge.setTextColor(c.similarity < 80
                            ? getColor(R.color.orange_accent) : getColor(R.color.text_secondary));
                    h.detail.setText(String.format(Locale.US,
                            "%d → %d 字节 (%+d)   相似度 %d%%",
                            c.oldSize, c.newSize, c.deltaSize(), c.similarity));
                    break;
            }
        }

        @Override
        public int getItemCount() {
            return rows.size();
        }
    }
}

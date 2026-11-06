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

    /**
     * 展开某个函数的指令级差异。
     *
     * <p>函数级相似度只能说"变了 40%"，看不出改了什么。这里把两版反汇编
     * 做 LCS，直接列出增删的指令。
     */
    private void showAsmDiff(SoDiff.FunctionChange c) {
        if (oldPath == null || newPath == null) return;
        tvSummary.setText("正在反汇编 " + c.name + " ...");

        new Thread(() -> {
            String oldAsm = disassembleOne(oldPath, c.oldOffset, c.oldSize);
            String newAsm = disassembleOne(newPath, c.newOffset, c.newSize);

            String text;
            if (oldAsm == null || newAsm == null) {
                text = "反汇编失败：函数大小未知，或该偏移读不到有效指令。";
            } else {
                com.example.anative.core.AsmDiff.Result r =
                        com.example.anative.core.AsmDiff.diff(oldAsm, newAsm);
                StringBuilder sb = new StringBuilder();
                sb.append(String.format(Locale.US, "指令重合率 %d%%   变动 %d 条\n\n",
                        r.similarity(), r.changeCount()));
                sb.append(com.example.anative.core.AsmDiff.renderText(r, 3));
                if (sb.length() > 6000) {
                    sb.setLength(6000);
                    sb.append("\n... （内容过长，已截断）");
                }
                text = sb.toString();
            }

            final String content = text;
            main.post(() -> {
                restoreSummary();
                new androidx.appcompat.app.AlertDialog.Builder(this)
                        .setTitle(c.name)
                        .setMessage(content)
                        .setPositiveButton("关闭", null)
                        .show();
            });
        }).start();
    }

    private void restoreSummary() {
        SoDiff.Result r = currentResult();
        tvSummary.setText(r == null ? "" : summaryText(r));
    }

    private String disassembleOne(String path, long va, long size) {
        try {
            if (size <= 0 || size > 65536) size = Math.min(4096, 65536);
            long off = com.example.anative.core.ElfParser.virtualAddrToFileOffset(path, va);
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(path, "r")) {
                if (off < 0 || off + 4 > raf.length()) return null;
                if (off + size > raf.length()) size = raf.length() - off;
                if (size <= 0) return null;
                byte[] bytes = new byte[(int) size];
                raf.seek(off);
                raf.readFully(bytes);
                return com.example.anative.core.DisasmBridge.disassembleStatic(
                        path, bytes, va, size, false, "", "", "");
            }
        } catch (Exception e) {
            return null;
        }
    }

    private SoDiff.Result currentResult() {
        return result;
    }

    private String summaryText(SoDiff.Result r) {
        return String.format(Locale.US,
                "变更 %d   新增 %d   删除 %d   未变 %d   整体相似度 %d%%",
                r.changed.size(), r.added.size(), r.removed.size(), r.same.size(), r.overallSimilarity());
    }

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
                            "%d → %d 字节 (%+d)   相似度 %d%%\n点击查看指令级差异",
                            c.oldSize, c.newSize, c.deltaSize(), c.similarity));
                    break;
            }

            if (SoDiff.KIND_CHANGED.equals(c.kind)) {
                h.itemView.setOnClickListener(v -> showAsmDiff(c));
            } else {
                h.itemView.setOnClickListener(null);
            }
        }

        @Override
        public int getItemCount() {
            return rows.size();
        }
    }
}

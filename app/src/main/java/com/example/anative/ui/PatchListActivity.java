package com.example.anative.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.PatchManager;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 修改记录：查看补丁差异、逐条撤销/重做、一键回滚与导出。
 */
public class PatchListActivity extends AppCompatActivity {

    private final List<PatchManager.Patch> items = new ArrayList<>();
    private Adapter adapter;
    private TextView tvSummary;
    private TextView tvEmpty;
    private MaterialButton btnUndoAll;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_patch_list);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        tvSummary = findViewById(R.id.tv_summary);
        tvEmpty = findViewById(R.id.tv_empty);
        btnUndoAll = findViewById(R.id.btn_undo_all);
        MaterialButton btnExport = findViewById(R.id.btn_export);

        RecyclerView recyclerView = findViewById(R.id.recycler_patches);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        adapter = new Adapter();
        recyclerView.setAdapter(adapter);

        btnUndoAll.setOnClickListener(v -> confirmUndoAll());
        btnExport.setOnClickListener(v -> exportPatch());
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    private void refresh() {
        items.clear();
        items.addAll(PatchManager.getInstance().getPatches());
        adapter.notifyDataSetChanged();

        int total = PatchManager.getInstance().getTotalCount();
        int active = PatchManager.getInstance().getActiveCount();
        tvSummary.setText(total == 0 ? "当前没有修改记录" : "共 " + total + " 条 · 生效 " + active + " 条");
        btnUndoAll.setEnabled(active > 0);
        tvEmpty.setVisibility(items.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void confirmUndoAll() {
        int active = PatchManager.getInstance().getActiveCount();
        if (active == 0) {
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("撤销全部修改")
                .setMessage("将把工作副本恢复为未修改状态，共 " + active + " 条。\n原始文件不会受影响。")
                .setPositiveButton("撤销", (dialog, which) -> {
                    int count = PatchManager.getInstance().undoAll();
                    refresh();
                    Toast.makeText(this, "已撤销 " + count + " 条", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void exportPatch() {
        if (PatchManager.getInstance().getActiveCount() == 0) {
            Toast.makeText(this, "没有生效中的修改", Toast.LENGTH_SHORT).show();
            return;
        }
        String text = PatchManager.getInstance().exportPatchText();
        try {
            File dir = new File(android.os.Environment.getExternalStorageDirectory(), "SoSandbox");
            if (!dir.exists() && !dir.mkdirs()) {
                dir = getExternalFilesDir(null);
            }
            String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
            File out = new File(dir, "patch_" + stamp + ".txt");
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(text.getBytes("UTF-8"));
                fos.getFD().sync();
            }
            String path = out.getAbsolutePath();
            new AlertDialog.Builder(this)
                    .setTitle("补丁已导出")
                    .setMessage(path)
                    .setPositiveButton("复制路径", (dialog, which) -> {
                        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                        if (cm != null) {
                            cm.setPrimaryClip(ClipData.newPlainText("patch", path));
                            Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
                        }
                    })
                    .setNegativeButton("关闭", null)
                    .show();
        } catch (Exception e) {
            Toast.makeText(this, "导出失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private class Adapter extends RecyclerView.Adapter<Adapter.VH> {

        class VH extends RecyclerView.ViewHolder {
            final TextView title;
            final TextView desc;
            final TextView diff;
            final MaterialButton undo;
            final MaterialButton redo;

            VH(@NonNull View itemView) {
                super(itemView);
                title = itemView.findViewById(R.id.tv_patch_title);
                desc = itemView.findViewById(R.id.tv_patch_desc);
                diff = itemView.findViewById(R.id.tv_patch_diff);
                undo = itemView.findViewById(R.id.btn_patch_undo);
                redo = itemView.findViewById(R.id.btn_patch_redo);
            }
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_patch, parent, false);
            return new VH(view);
        }

        @Override
        public void onBindViewHolder(@NonNull VH holder, int position) {
            PatchManager.Patch patch = items.get(position);
            holder.title.setText(String.format(Locale.US, "#%d  %s  %s  %s",
                    patch.id, patch.addressText(), patch.timeText(), patch.kind));
            holder.desc.setText(patch.description.isEmpty() ? "（无描述）" : patch.description);
            holder.diff.setText("- " + hex(patch.oldBytes) + "\n+ " + hex(patch.newBytes));
            holder.diff.setTextColor(getResources().getColor(
                    patch.undone ? R.color.text_secondary : R.color.text_primary));

            holder.undo.setEnabled(!patch.undone);
            holder.redo.setEnabled(patch.undone);
            holder.undo.setAlpha(patch.undone ? 0.4f : 1f);
            holder.redo.setAlpha(patch.undone ? 1f : 0.4f);

            holder.undo.setOnClickListener(v -> {
                try {
                    if (PatchManager.getInstance().undo(patch.id)) {
                        refresh();
                        Toast.makeText(PatchListActivity.this, "已撤销 #" + patch.id, Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Toast.makeText(PatchListActivity.this, "撤销失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            });
            holder.redo.setOnClickListener(v -> {
                try {
                    if (PatchManager.getInstance().redo(patch.id)) {
                        refresh();
                        Toast.makeText(PatchListActivity.this, "已重做 #" + patch.id, Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Toast.makeText(PatchListActivity.this, "重做失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            });
        }

        @Override
        public int getItemCount() {
            return items.size();
        }
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format(Locale.US, "%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }
}

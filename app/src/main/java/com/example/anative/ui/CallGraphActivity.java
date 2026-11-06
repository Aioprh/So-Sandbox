package com.example.anative.ui;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.example.anative.R;
import com.example.anative.core.CallGraph;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefScanner;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Locale;

/**
 * 调用关系视图。
 *
 * <p>以指定函数为中心做 ego 图展开：能看到"谁调用了它"和"它调用了谁"。
 * 交叉引用数据来自 {@link XRefScanner}，首次使用会在后台扫描 .text，
 * 大文件需要几秒到十几秒。
 */
public class CallGraphActivity extends AppCompatActivity {

    private static final String[] DEPTH_LABELS = {"展开 1 层", "展开 2 层", "展开 3 层"};
    private static final String[] DIR_LABELS = {"双向", "只看被调用", "只看调用者"};

    private final Handler main = new Handler(Looper.getMainLooper());

    private EditText etCenter;
    private TextView tvHint;
    private TextView tvGraph;
    private MaterialButton btnExport;
    private Spinner spDepth;
    private Spinner spDirection;

    private CallGraph current;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_call_graph);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        etCenter = findViewById(R.id.et_center);
        tvHint = findViewById(R.id.tv_hint);
        tvGraph = findViewById(R.id.tv_graph);
        btnExport = findViewById(R.id.btn_export);
        spDepth = findViewById(R.id.sp_depth);
        spDirection = findViewById(R.id.sp_direction);

        spDepth.setAdapter(new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item, DEPTH_LABELS));
        spDepth.setSelection(1);
        spDirection.setAdapter(new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_dropdown_item, DIR_LABELS));

        findViewById(R.id.btn_build).setOnClickListener(v -> build());
        btnExport.setOnClickListener(v -> chooseExport());

        // 预填：进入时若有已选函数，直接用它
        String prefill = getIntent().getStringExtra("function_name");
        if (prefill != null && !prefill.isEmpty()) {
            etCenter.setText(prefill);
        } else if (DataHolder.getInstance().getSoPath() == null) {
            tvHint.setText("请先在主界面加载一个 SO。");
        } else {
            List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
            if (funcs != null && !funcs.isEmpty()) {
                etCenter.setText(funcs.get(0).getDemangledName());
            }
        }
    }

    private void build() {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) {
            Toast.makeText(this, "尚未加载 SO", Toast.LENGTH_SHORT).show();
            return;
        }
        String query = etCenter.getText().toString().trim();
        if (query.isEmpty()) {
            Toast.makeText(this, "请输入函数名或偏移", Toast.LENGTH_SHORT).show();
            return;
        }

        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        NativeFunction center = resolve(funcs, query);
        if (center == null) {
            Toast.makeText(this, "没有找到匹配的函数", Toast.LENGTH_SHORT).show();
            return;
        }

        int depth = spDepth.getSelectedItemPosition() + 1;
        int direction = 0;
        int dirIdx = spDirection.getSelectedItemPosition();
        if (dirIdx == 1) direction = 1;
        else if (dirIdx == 2) direction = -1;
        final int dir = direction;

        tvHint.setText("正在扫描交叉引用…");
        tvGraph.setText("");

        new Thread(() -> {
            String error = null;
            CallGraph graph = null;
            try {
                XRefScanner scanner = DataHolder.getInstance().getXRefScanner();
                if (scanner == null) {
                    scanner = new XRefScanner();
                    DataHolder.getInstance().setXRefScanner(scanner);
                }
                if (!scanner.isScanned()) {
                    scanner.scan(soPath, funcs, DataHolder.getInstance().getStrings());
                }
                graph = CallGraph.ego(scanner, funcs, center.getOffset(), dir, depth, 400);
            } catch (Exception e) {
                error = e.getMessage();
            }
            final CallGraph fg = graph;
            final String fe = error;
            final String fname = center.getDemangledName();
            final long foff = center.getOffset();
            main.post(() -> {
                if (fe != null || fg == null) {
                    tvHint.setText("生成失败：" + fe);
                    return;
                }
                current = fg;
                btnExport.setEnabled(true);
                tvHint.setText(String.format(Locale.US,
                        "中心：%s @0x%X   节点 %d   边 %d%s",
                        fname, foff, fg.nodes.size(), fg.edges.size(),
                        fg.truncated ? "（已达节点上限，结果被截断）" : ""));
                tvGraph.setText(fg.toText(200));
                if (fg.nodes.size() <= 1) {
                    tvGraph.setText(fg.toText(200)
                            + "\n没有找到交叉引用。可能原因：\n"
                            + "  · 该函数未被调用，也没有调用其它函数\n"
                            + "  · 交叉引用依赖 .text 段扫描，加固样本可能被拆分\n"
                            + "  · ARM32 只识别 BL/BLX 直接调用，寄存器间接调用无法解析\n");
                }
            });
        }, "call-graph").start();
    }

    private NativeFunction resolve(List<NativeFunction> funcs, String query) {
        if (funcs == null) return null;
        String q = query.trim();
        // 0x 前缀或纯十六进制 → 按偏移匹配最近函数
        if (q.startsWith("0x") || q.startsWith("0X")) {
            try {
                long off = Long.parseLong(q.substring(2), 16);
                NativeFunction best = null;
                for (NativeFunction f : funcs) {
                    if (f.getOffset() <= off
                            && (best == null || f.getOffset() > best.getOffset())) {
                        best = f;
                    }
                }
                return best;
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        for (NativeFunction f : funcs) {
            if (q.equals(f.getName()) || q.equals(f.getDemangledName())) return f;
        }
        for (NativeFunction f : funcs) {
            String n = f.getDemangledName();
            if (n != null && n.contains(q)) return f;
        }
        return null;
    }

    private void chooseExport() {
        if (current == null) return;
        new AlertDialog.Builder(this)
                .setTitle("导出格式")
                .setItems(new String[]{"Graphviz DOT（可生成图片）", "Mermaid（可贴进文档）", "纯文本邻接表"},
                        (d, which) -> export(which))
                .show();
    }

    private void export(int which) {
        String content;
        String ext;
        if (which == 0) {
            content = current.toDot(true);
            ext = "dot";
        } else if (which == 1) {
            content = current.toMermaid();
            ext = "mmd";
        } else {
            content = current.toText(500);
            ext = "txt";
        }

        try {
            File dir = new File(android.os.Environment.getExternalStorageDirectory(), "SoSandbox");
            if (!dir.exists() && !dir.mkdirs()) {
                Toast.makeText(this, "无法创建目录", Toast.LENGTH_LONG).show();
                return;
            }
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
                    .format(new java.util.Date());
            File out = new File(dir, "callgraph_" + stamp + "." + ext);
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(content.getBytes("UTF-8"));
            }
            Toast.makeText(this, "已导出：" + out.getAbsolutePath(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "导出失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }
}

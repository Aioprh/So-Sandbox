package com.example.anative.ui;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.AsmSearch;
import com.example.anative.core.DataHolder;
import com.example.anative.core.DisasmTables;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.PltEntry;
import com.google.android.material.appbar.MaterialToolbar;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 汇编模式搜索：把"哪些函数调了 X"变成一次查询。
 */
public class AsmSearchActivity extends AppCompatActivity {

    private static final int MAX_HITS = 400;
    private static final int MAX_FUNCTIONS = 6000;

    private final List<AsmSearch.Hit> hits = new ArrayList<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean cancel = new AtomicBoolean(false);

    private Adapter adapter;
    private TextView tvStatus;
    private ProgressBar progress;
    private Button btnSearch;
    private EditText etQuery;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_asm_search);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        etQuery = findViewById(R.id.et_query);
        tvStatus = findViewById(R.id.tv_status);
        progress = findViewById(R.id.progress);
        btnSearch = findViewById(R.id.btn_search);

        RecyclerView recycler = findViewById(R.id.recycler_hits);
        recycler.setLayoutManager(new LinearLayoutManager(this));
        adapter = new Adapter();
        recycler.setAdapter(adapter);

        btnSearch.setOnClickListener(v -> startSearch());
        etQuery.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_SEARCH) {
                startSearch();
                return true;
            }
            return false;
        });
    }

    private void startSearch() {
        String query = etQuery.getText().toString().trim();
        if (query.isEmpty()) {
            tvStatus.setText("请输入查询条件");
            return;
        }

        DataHolder holder = DataHolder.getInstance();
        String soPath = holder.getSoPath();
        List<NativeFunction> functions = holder.getFunctions();
        if (soPath == null || functions == null || functions.isEmpty()) {
            tvStatus.setText("尚未加载 SO 文件");
            return;
        }

        cancel.set(false);
        hits.clear();
        adapter.notifyDataSetChanged();

        btnSearch.setEnabled(false);
        progress.setVisibility(View.VISIBLE);
        progress.setProgress(0);
        tvStatus.setText("准备中...");

        List<ElfParser.StringEntry> strings = holder.getStrings();
        List<PltEntry> plt = holder.getPltEntries();

        executor.execute(() -> {
            String funcTable = DisasmTables.funcTable(functions);
            String pltTable = DisasmTables.pltTable(plt);
            String strTable = DisasmTables.stringTable(strings);

            List<AsmSearch.Hit> result = AsmSearch.search(
                    soPath, functions, query,
                    funcTable, pltTable, strTable,
                    MAX_HITS, MAX_FUNCTIONS,
                    (done, total, current) -> handler.post(() -> {
                        progress.setProgress(total <= 0 ? 0 : (int) (done * 100L / total));
                        tvStatus.setText(String.format(Locale.US,
                                "已扫描 %d / %d 个函数，命中 %d 条\n当前: %s",
                                done, total, hits.size(), current));
                    }),
                    cancel);

            handler.post(() -> {
                btnSearch.setEnabled(true);
                progress.setVisibility(View.GONE);
                hits.clear();
                hits.addAll(result);
                adapter.notifyDataSetChanged();

                if (result.isEmpty()) {
                    tvStatus.setText("没有命中。换个写法试试：\n"
                            + "· m:bl 只匹配助记符\n"
                            + "· /ldr\\s+x0/ 用正则\n"
                            + "· 搜索注释里的库函数名（如 memcpy）");
                } else {
                    int funcs = countDistinctFunctions(result);
                    tvStatus.setText(String.format(Locale.US,
                            "命中 %d 条指令，分布在 %d 个函数中", result.size(), funcs));
                }
            });
        });
    }

    private int countDistinctFunctions(List<AsmSearch.Hit> list) {
        java.util.HashSet<Long> set = new java.util.HashSet<>();
        for (AsmSearch.Hit h : list) set.add(h.function.getOffset());
        return set.size();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        cancel.set(true);
        executor.shutdownNow();
    }

    private class Adapter extends RecyclerView.Adapter<Adapter.Holder> {

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_asm_hit, parent, false);
            return new Holder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
            AsmSearch.Hit h = hits.get(position);
            holder.func.setText(String.format(Locale.US, "%s  @0x%X",
                    h.function.getDemangledName(), h.function.getOffset()));
            holder.instruction.setText(h.text);
        }

        @Override
        public int getItemCount() {
            return hits.size();
        }

        class Holder extends RecyclerView.ViewHolder {
            final TextView func;
            final TextView instruction;

            Holder(@NonNull View itemView) {
                super(itemView);
                func = itemView.findViewById(R.id.tv_func);
                instruction = itemView.findViewById(R.id.tv_instruction);
            }
        }
    }
}

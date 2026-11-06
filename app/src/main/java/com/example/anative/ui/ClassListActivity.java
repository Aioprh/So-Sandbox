package com.example.anative.ui;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.CppRtti;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeFunction;
import com.google.android.material.appbar.MaterialToolbar;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * C++ 类视图：把 RTTI 还原出的类名、基类、虚函数表列出来。
 *
 * <p>对 C++ 写的库，函数列表只有一堆 mangled 名字，看不出类的结构。
 * 这里按类聚合虚函数，点击可以看每个槽位指向哪个函数。
 */
public class ClassListActivity extends AppCompatActivity {

    private final List<CppRtti.RttiClass> all = new ArrayList<>();
    private final List<CppRtti.RttiClass> shown = new ArrayList<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    private Adapter adapter;
    private TextView tvHint;
    private TextView tvSummary;
    private ProgressBar progress;
    private CppRtti.Result result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_class_list);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        tvHint = findViewById(R.id.tv_hint);
        tvSummary = findViewById(R.id.tv_summary);
        progress = findViewById(R.id.progress);

        RecyclerView recycler = findViewById(R.id.recycler_classes);
        recycler.setLayoutManager(new LinearLayoutManager(this));
        adapter = new Adapter();
        recycler.setAdapter(adapter);

        EditText etFilter = findViewById(R.id.et_filter);
        etFilter.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                applyFilter(s.toString());
            }
        });

        load();
    }

    private void load() {
        String soPath = DataHolder.getInstance().getSoPath();
        List<NativeFunction> functions = DataHolder.getInstance().getFunctions();
        if (soPath == null) {
            tvHint.setText("尚未加载 SO 文件");
            progress.setVisibility(View.GONE);
            return;
        }

        progress.setVisibility(View.VISIBLE);
        tvHint.setVisibility(View.VISIBLE);
        tvHint.setText("正在解析 RTTI...");

        executor.execute(() -> {
            CppRtti.Result r = null;
            String error = null;
            try {
                r = CppRtti.scan(soPath, functions == null ? new ArrayList<>() : functions);
            } catch (Exception e) {
                error = e.getMessage();
            }

            final CppRtti.Result finalResult = r;
            final String finalError = error;
            handler.post(() -> {
                progress.setVisibility(View.GONE);
                if (finalError != null) {
                    tvHint.setText("解析失败: " + finalError);
                    return;
                }
                result = finalResult;
                all.clear();
                all.addAll(finalResult.classes);
                tvSummary.setText(CppRtti.summary(finalResult));
                if (all.isEmpty()) {
                    tvHint.setText(finalResult.note != null ? finalResult.note
                            : "没有找到虚表。可能是 C 库，或 RTTI 被编译选项关掉了（-fno-rtti）");
                    return;
                }
                tvHint.setVisibility(View.GONE);
                applyFilter("");
            });
        });
    }

    private void applyFilter(String raw) {
        String q = raw == null ? "" : raw.trim().toLowerCase(Locale.US);
        shown.clear();
        for (CppRtti.RttiClass c : all) {
            if (q.isEmpty()
                    || (c.className != null && c.className.toLowerCase(Locale.US).contains(q))
                    || c.code.toLowerCase(Locale.US).contains(q)) {
                shown.add(c);
            }
        }
        adapter.notifyDataSetChanged();
        if (shown.isEmpty() && !all.isEmpty()) {
            tvHint.setVisibility(View.VISIBLE);
            tvHint.setText("没有匹配的类");
        } else if (!shown.isEmpty()) {
            tvHint.setVisibility(View.GONE);
        }
    }

    private void showDetail(CppRtti.RttiClass c) {
        StringBuilder sb = new StringBuilder();
        sb.append("vtable: 0x").append(String.format(Locale.US, "%X", c.vtableVa));
        if (c.typeinfoVa != 0) {
            sb.append("\ntypeinfo: 0x").append(String.format(Locale.US, "%X", c.typeinfoVa));
        }
        sb.append("\n\n");

        if (c.slots.isEmpty()) {
            sb.append("没有虚函数槽");
        } else {
            for (CppRtti.VirtualFunction vf : c.slots) {
                sb.append(String.format(Locale.US, "[%2d] ", vf.index));
                if (vf.codePointer) {
                    sb.append(vf.display());
                    if (vf.targetName == null || vf.targetName.isEmpty()) {
                        sb.append("   （未识别为已有函数）");
                    }
                } else {
                    sb.append("0x").append(String.format(Locale.US, "%X", vf.targetVa))
                            .append("   （非代码指针，可能是调整 thunk）");
                }
                sb.append('\n');
            }
        }

        new AlertDialog.Builder(this)
                .setTitle(c.className)
                .setMessage(sb.toString())
                .setPositiveButton("关闭", null)
                .show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    private class Adapter extends RecyclerView.Adapter<Adapter.Holder> {

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_class, parent, false);
            return new Holder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
            CppRtti.RttiClass c = shown.get(position);
            holder.name.setText(c.className != null ? c.className : c.code);

            StringBuilder meta = new StringBuilder();
            meta.append(c.slots.size()).append(" 个虚函数");
            if (c.baseClass != null && !c.baseClass.isEmpty()) {
                meta.append("  ·  基类 ").append(c.baseClass);
            }
            meta.append(String.format(Locale.US, "  ·  @0x%X", c.vtableVa));
            holder.meta.setText(meta.toString());

            holder.itemView.setOnClickListener(v -> showDetail(c));
        }

        @Override
        public int getItemCount() {
            return shown.size();
        }

        class Holder extends RecyclerView.ViewHolder {
            final TextView name;
            final TextView meta;

            Holder(@NonNull View itemView) {
                super(itemView);
                name = itemView.findViewById(R.id.tv_class_name);
                meta = itemView.findViewById(R.id.tv_class_meta);
            }
        }
    }
}

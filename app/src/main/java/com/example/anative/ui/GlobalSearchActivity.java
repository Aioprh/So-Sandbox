package com.example.anative.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.AnalysisCache;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.google.android.material.appbar.MaterialToolbar;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 全局搜索：一次搜函数名、地址与字符串内容。
 */
public class GlobalSearchActivity extends AppCompatActivity {

    private static final int MAX_RESULTS = 300;

    private final List<Item> results = new ArrayList<>();
    private String lastQuery = "";
    private boolean loadingStrings;
    private Adapter adapter;
    private TextView tvHint;
    private RecyclerView recyclerView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_global_search);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        EditText etSearch = findViewById(R.id.et_search);
        tvHint = findViewById(R.id.tv_hint);
        recyclerView = findViewById(R.id.recycler_results);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        adapter = new Adapter();
        recyclerView.setAdapter(adapter);

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                search(s.toString());
            }
        });

        etSearch.requestFocus();
        search("");
    }

    private void search(String raw) {
        String query = raw == null ? "" : raw.trim().toLowerCase(Locale.US);
        lastQuery = query;
        results.clear();

        if (query.isEmpty()) {
            tvHint.setText("输入函数名、地址（如 1a2b）或字符串关键字");
            tvHint.setVisibility(View.VISIBLE);
            recyclerView.setVisibility(View.GONE);
            adapter.notifyDataSetChanged();
            return;
        }

        DataHolder holder = DataHolder.getInstance();
        maybeLoadStrings(holder);
        List<NativeFunction> functions = holder.getFunctions();
        if (functions != null) {
            for (NativeFunction function : functions) {
                if (results.size() >= MAX_RESULTS) {
                    break;
                }
                String name = function.getName() == null ? "" : function.getName();
                String demangled = function.getDemangledName() == null ? "" : function.getDemangledName();
                String address = String.format(Locale.US, "%X", function.getOffset());
                if (name.toLowerCase(Locale.US).contains(query)
                        || demangled.toLowerCase(Locale.US).contains(query)
                        || address.toLowerCase(Locale.US).contains(query.replace("0x", ""))) {
                    results.add(Item.function(function, demangled.isEmpty() ? name : demangled));
                }
            }
        }

        List<ElfParser.StringEntry> strings = holder.getStrings();
        if (strings != null) {
            for (ElfParser.StringEntry entry : strings) {
                if (results.size() >= MAX_RESULTS) {
                    break;
                }
                if (entry == null || entry.value == null) {
                    continue;
                }
                String address = String.format(Locale.US, "%X", entry.virtualAddress);
                if (entry.value.toLowerCase(Locale.US).contains(query)
                        || address.toLowerCase(Locale.US).contains(query.replace("0x", ""))) {
                    results.add(Item.string(entry));
                }
            }
        }

        adapter.notifyDataSetChanged();
        boolean empty = results.isEmpty();
        tvHint.setVisibility(empty ? View.VISIBLE : View.GONE);
        recyclerView.setVisibility(empty ? View.GONE : View.VISIBLE);
        if (empty) {
            tvHint.setText("没有匹配结果\n请先加载 SO，或换一个关键字");
        }
    }

    /**
     * 字符串表默认按需加载；搜索时如果还没加载，后台补一次再重搜。
     */
    private void maybeLoadStrings(DataHolder holder) {
        if (loadingStrings || holder.getStrings() != null) {
            return;
        }
        final String soPath = holder.getSoPath();
        if (soPath == null || soPath.isEmpty()) {
            return;
        }
        loadingStrings = true;
        tvHint.setText("正在加载字符串表…");
        new Thread(() -> {
            try {
                List<ElfParser.StringEntry> strings = AnalysisCache.strings(this, soPath);
                holder.setStrings(strings);
            } catch (Exception ignored) {
                // 解析失败时保持空表，不阻塞函数搜索
            }
            runOnUiThread(() -> {
                loadingStrings = false;
                search(lastQuery);
            });
        }, "search-load-strings").start();
    }

    private static class Item {
        static final int TYPE_FUNCTION = 0;
        static final int TYPE_STRING = 1;

        final int type;
        final String title;
        final String subtitle;
        final long address;
        final NativeFunction function;
        final String content;

        private Item(int type, String title, String subtitle, long address,
                     NativeFunction function, String content) {
            this.type = type;
            this.title = title;
            this.subtitle = subtitle;
            this.address = address;
            this.function = function;
            this.content = content;
        }

        static Item function(NativeFunction function, String displayName) {
            return new Item(TYPE_FUNCTION, displayName,
                    "函数 · " + function.getSize() + " 字节 · " + function.getSource(),
                    function.getOffset(), function, null);
        }

        static Item string(ElfParser.StringEntry entry) {
            String text = entry.value.length() > 120 ? entry.value.substring(0, 120) + "…" : entry.value;
            return new Item(TYPE_STRING, text, "字符串 · " + entry.section, entry.virtualAddress, null, entry.value);
        }
    }

    private class Adapter extends RecyclerView.Adapter<Adapter.VH> {

        class VH extends RecyclerView.ViewHolder {
            final TextView badge;
            final TextView title;
            final TextView subtitle;

            VH(@NonNull View itemView) {
                super(itemView);
                badge = itemView.findViewById(R.id.tv_type);
                title = itemView.findViewById(R.id.tv_title);
                subtitle = itemView.findViewById(R.id.tv_subtitle);
            }
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new VH(LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_search_result, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull VH holder, int position) {
            Item item = results.get(position);
            holder.badge.setText(item.type == Item.TYPE_FUNCTION ? "F" : "S");
            holder.badge.setBackgroundResource(item.type == Item.TYPE_FUNCTION
                    ? R.drawable.bg_badge_function : R.drawable.bg_badge_string);
            holder.title.setText(item.title);
            holder.subtitle.setText(String.format(Locale.US, "0x%X  ·  %s", item.address, item.subtitle));

            holder.itemView.setOnClickListener(v -> {
                if (item.type == Item.TYPE_FUNCTION) {
                    openFunction(item.function);
                } else {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("string", item.content));
                        Toast.makeText(GlobalSearchActivity.this,
                                "已复制字符串（0x" + Long.toHexString(item.address).toUpperCase(Locale.US) + "）",
                                Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        @Override
        public int getItemCount() {
            return results.size();
        }
    }

    private void openFunction(NativeFunction function) {
        Intent intent = new Intent(this, FunctionDetailActivity.class);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, function.getName());
        intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, function.getDemangledName());
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, function.getOffset());
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, function.getSize());
        intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, function.getSignatureString());
        startActivity(intent);
    }
}

package com.example.anative.ui;

import android.Manifest;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.example.anative.R;
import com.example.anative.mcp.McpLog;
import com.example.anative.mcp.McpManager;
import com.example.anative.mcp.McpPrefs;
import com.example.anative.mcp.McpProtocol;
import com.example.anative.mcp.McpService;
import com.google.android.material.appbar.MaterialToolbar;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * MCP 服务设置页：开关、端口、令牌、连接信息与运行日志。
 */
public class McpActivity extends AppCompatActivity {

    private static final int REQUEST_NOTIFICATION = 4001;

    private SwitchCompat switchMcp;
    private SwitchCompat switchReadOnly;
    private TextView tvStatus;
    private TextView tvEndpoint;
    private TextView tvSse;
    private TextView tvPort;
    private TextView tvToken;
    private TextView tvTools;
    private TextView tvClient;
    private TextView tvLog;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean suppressSwitchCallback = false;
    private int cachedToolCount;

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            refreshStatus();
            tvLog.setText(McpLog.dump());
            handler.postDelayed(this, 1500);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_mcp);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        switchMcp = findViewById(R.id.switch_mcp);
        switchReadOnly = findViewById(R.id.switch_read_only);
        tvStatus = findViewById(R.id.tv_status);
        tvEndpoint = findViewById(R.id.tv_endpoint);
        tvSse = findViewById(R.id.tv_sse);
        tvPort = findViewById(R.id.tv_port);
        tvToken = findViewById(R.id.tv_token);
        tvTools = findViewById(R.id.tv_tools);
        tvClient = findViewById(R.id.tv_client);
        tvLog = findViewById(R.id.tv_log);

        switchReadOnly.setChecked(McpPrefs.isReadOnly(this));
        switchReadOnly.setOnCheckedChangeListener((buttonView, isChecked) -> {
            McpPrefs.setReadOnly(McpActivity.this, isChecked);
            McpLog.info(isChecked ? "已开启只读模式" : "已关闭只读模式");
        });

        bindActions();
    }

    private void bindActions() {
        switchMcp.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (suppressSwitchCallback) {
                return;
            }
            if (isChecked) {
                enableServer();
            } else {
                disableServer();
            }
        });

        findViewById(R.id.card_endpoint).setOnClickListener(v -> {
            String endpoint = "http://" + McpPrefs.localIpAddress() + ":" + McpPrefs.getPort(this) + "/mcp";
            copy(endpoint);
        });

        findViewById(R.id.card_port).setOnClickListener(v -> showPortDialog());
        findViewById(R.id.card_token).setOnClickListener(v -> showTokenDialog());
        findViewById(R.id.card_tools).setOnClickListener(v -> showToolsDialog());
        findViewById(R.id.card_config).setOnClickListener(v -> showConfigDialog());
        findViewById(R.id.btn_clear_log).setOnClickListener(v -> {
            McpLog.clear();
            tvLog.setText(McpLog.dump());
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();
        handler.post(refreshRunnable);
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(refreshRunnable);
    }

    // ==================== 状态刷新 ====================

    private void refreshStatus() {
        boolean running = McpManager.isRunning();
        int port = McpPrefs.getPort(this);
        String ip = McpPrefs.localIpAddress();

        suppressSwitchCallback = true;
        switchMcp.setChecked(running);
        suppressSwitchCallback = false;

        if (running) {
            tvStatus.setText("运行中 · " + ip + ":" + McpManager.getPort()
                    + " · " + McpManager.getToolCount() + " 个工具");
        } else {
            tvStatus.setText(McpPrefs.isEnabled(this) ? "已启用，但服务未运行" : "未启动");
        }

        tvEndpoint.setText("http://" + ip + ":" + port + "/mcp");
        tvSse.setText("http://" + ip + ":" + port + "/sse");
        tvPort.setText(String.valueOf(port));

        boolean auth = McpPrefs.isAuthRequired(this);
        String token = McpPrefs.getToken(this);
        if (!auth) {
            tvToken.setText("未校验（局域网内任何人都可连接）");
        } else if (token.isEmpty()) {
            tvToken.setText("未生成");
        } else {
            tvToken.setText(mask(token));
        }

        tvTools.setText(toolCount() + " 个工具（点击查看）");

        String client = McpPrefs.getLastClient(this);
        tvClient.setText(client == null || client.isEmpty() ? "未接入客户端" : "最近接入: " + client);
    }

    private int toolCount() {
        if (cachedToolCount <= 0) {
            int count = McpManager.getToolCount();
            if (count <= 0) {
                count = new McpProtocol(getApplicationContext()).toolCount();
            }
            cachedToolCount = count;
        }
        return cachedToolCount;
    }

    private static String mask(String token) {
        if (token.length() <= 10) {
            return token;
        }
        return token.substring(0, 6) + "..." + token.substring(token.length() - 4);
    }

    // ==================== 开关 ====================

    private void enableServer() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQUEST_NOTIFICATION);
        }
        try {
            McpPrefs.ensureToken(this);
            Intent intent = new Intent(this, McpService.class);
            intent.setAction(McpService.ACTION_START);
            ContextCompat.startForegroundService(this, intent);
            Toast.makeText(this, "MCP 服务启动中", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            McpLog.error("启动失败: " + e.getMessage());
            Toast.makeText(this, "启动失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
            suppressSwitchCallback = true;
            switchMcp.setChecked(false);
            suppressSwitchCallback = false;
        }
        handler.postDelayed(this::refreshStatus, 400);
    }

    private void disableServer() {
        Intent intent = new Intent(this, McpService.class);
        intent.setAction(McpService.ACTION_STOP);
        startService(intent);
        McpManager.stop(this);
        handler.postDelayed(this::refreshStatus, 300);
        Toast.makeText(this, "MCP 服务已停止", Toast.LENGTH_SHORT).show();
    }

    private void restartIfRunning() {
        if (!McpManager.isRunning()) {
            return;
        }
        try {
            McpManager.restart(this);
        } catch (Exception e) {
            McpLog.error("重启失败: " + e.getMessage());
            Toast.makeText(this, "重启失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
        handler.postDelayed(this::refreshStatus, 300);
    }

    // ==================== 对话框 ====================

    private void showPortDialog() {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setText(String.valueOf(McpPrefs.getPort(this)));
        input.setSelection(input.getText().length());

        new AlertDialog.Builder(this)
                .setTitle("监听端口")
                .setMessage("建议使用 1024-65535 之间未被占用的端口。修改后服务会自动重启。")
                .setView(input)
                .setPositiveButton("保存", (dialog, which) -> {
                    String text = input.getText().toString().trim();
                    int port;
                    try {
                        port = Integer.parseInt(text);
                    } catch (NumberFormatException e) {
                        Toast.makeText(this, "端口格式不正确", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    if (port < 1024 || port > 65535) {
                        Toast.makeText(this, "端口需在 1024-65535 之间", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    McpPrefs.setPort(this, port);
                    restartIfRunning();
                    refreshStatus();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showTokenDialog() {
        final String token = McpPrefs.getToken(this);
        boolean auth = McpPrefs.isAuthRequired(this);
        String message = auth
                ? "客户端需在请求头带上 Authorization: Bearer <令牌>。\n当前令牌：\n" + (token.isEmpty() ? "（未生成）" : token)
                : "当前已关闭令牌校验，同一局域网内任何人都可以连接（风险较高）。";

        new AlertDialog.Builder(this)
                .setTitle("访问令牌")
                .setMessage(message)
                .setPositiveButton("复制", (d, w) -> copy(McpPrefs.ensureToken(this)))
                .setNeutralButton("重新生成", (d, w) -> {
                    McpPrefs.setToken(this, McpPrefs.randomToken());
                    restartIfRunning();
                    refreshStatus();
                    Toast.makeText(this, "令牌已重新生成", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(auth ? "关闭校验" : "开启校验", (d, w) -> {
                    McpPrefs.setAuthRequired(this, !auth);
                    if (!auth) {
                        McpPrefs.ensureToken(this);
                    }
                    restartIfRunning();
                    refreshStatus();
                })
                .show();
    }

    private void showToolsDialog() {
        StringBuilder sb = new StringBuilder();
        try {
            JSONArray tools = new McpProtocol(this).toolDefinitions();
            for (int i = 0; i < tools.length(); i++) {
                JSONObject tool = tools.getJSONObject(i);
                sb.append("• ").append(tool.optString("name")).append('\n');
                sb.append("   ").append(tool.optString("description")).append("\n\n");
            }
        } catch (Exception e) {
            sb.append("读取工具列表失败: ").append(e.getMessage());
        }

        new AlertDialog.Builder(this)
                .setTitle("可用工具")
                .setMessage(sb.toString())
                .setPositiveButton("关闭", null)
                .setNeutralButton("复制", (d, w) -> copy(sb.toString()))
                .show();
    }

    private void showConfigDialog() {
        String ip = McpPrefs.localIpAddress();
        int port = McpPrefs.getPort(this);
        String token = McpPrefs.isAuthRequired(this) ? McpPrefs.ensureToken(this) : "";
        String json = "{\n"
                + "  \"mcpServers\": {\n"
                + "    \"so-sandbox\": {\n"
                + "      \"type\": \"http\",\n"
                + "      \"url\": \"http://" + ip + ":" + port + "/mcp\",\n"
                + "      \"headers\": {\n"
                + "        \"Authorization\": \"Bearer " + token + "\"\n"
                + "      }\n"
                + "    }\n"
                + "  }\n"
                + "}";

        new AlertDialog.Builder(this)
                .setTitle("客户端配置")
                .setMessage("把下面的配置粘贴到 MCP 客户端（Claude Desktop / Cursor / Cherry Studio 等）的配置文件中。\n\n" + json)
                .setPositiveButton("复制", (d, w) -> copy(json))
                .setNegativeButton("关闭", null)
                .show();
    }

    private void copy(String text) {
        ClipboardManager manager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (manager == null) {
            return;
        }
        manager.setPrimaryClip(ClipData.newPlainText("mcp", text));
        Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_NOTIFICATION) {
            // 通知权限仅影响通知是否可见，服务本身仍可启动
            refreshStatus();
        }
    }
}

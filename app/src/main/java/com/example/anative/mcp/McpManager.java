package com.example.anative.mcp;

import android.content.Context;

import java.io.IOException;

/**
 * MCP 服务生命周期管理（单例持有服务器实例）。
 */
public final class McpManager {

    private static McpServer server;

    private McpManager() {
    }

    private static synchronized McpServer server(Context context) {
        if (server == null) {
            server = new McpServer(context.getApplicationContext());
            McpLog.info("MCP 服务器实例已创建");
        }
        return server;
    }

    /**
     * 按当前设置启动服务（端口、令牌取自 McpPrefs）。
     */
    public static synchronized void start(Context context) throws IOException {
        McpServer instance = server(context);
        if (instance.isRunning()) {
            return;
        }
        String token = McpPrefs.isAuthRequired(context) ? McpPrefs.ensureToken(context) : "";
        instance.start(McpPrefs.getPort(context), token);
        McpPrefs.setEnabled(context, true);
    }

    public static synchronized void stop(Context context) {
        if (server != null) {
            server.stop();
        }
        McpPrefs.setEnabled(context, false);
    }

    /**
     * 端口/令牌变更后重启服务。
     */
    public static synchronized void restart(Context context) throws IOException {
        if (server != null) {
            server.stop();
        }
        start(context);
    }

    public static synchronized boolean isRunning() {
        return server != null && server.isRunning();
    }

    public static synchronized int getPort() {
        return server == null ? 0 : server.getPort();
    }

    public static synchronized int getToolCount() {
        return server == null ? 0 : server.getToolCount();
    }
}

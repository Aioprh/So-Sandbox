package com.example.anative.mcp;

import android.content.Context;
import android.content.SharedPreferences;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

/**
 * MCP 服务的配置项（复用 app_prefs）。
 */
public final class McpPrefs {

    public static final String PREFS_NAME = "app_prefs";
    public static final String KEY_ENABLED = "mcp_enabled";
    public static final String KEY_PORT = "mcp_port";
    public static final String KEY_TOKEN = "mcp_token";
    public static final String KEY_AUTH = "mcp_auth_required";
    public static final String KEY_LAST_CLIENT = "mcp_last_client";

    public static final int DEFAULT_PORT = 8765;

    private McpPrefs() {
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static boolean isEnabled(Context context) {
        return prefs(context).getBoolean(KEY_ENABLED, false);
    }

    public static void setEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_ENABLED, enabled).apply();
    }

    public static int getPort(Context context) {
        int port = prefs(context).getInt(KEY_PORT, DEFAULT_PORT);
        if (port < 1024 || port > 65535) {
            return DEFAULT_PORT;
        }
        return port;
    }

    public static void setPort(Context context, int port) {
        prefs(context).edit().putInt(KEY_PORT, port).apply();
    }

    public static boolean isAuthRequired(Context context) {
        return prefs(context).getBoolean(KEY_AUTH, true);
    }

    public static void setAuthRequired(Context context, boolean required) {
        prefs(context).edit().putBoolean(KEY_AUTH, required).apply();
    }

    /**
     * 当前令牌，未生成时返回空串。
     */
    public static String getToken(Context context) {
        String token = prefs(context).getString(KEY_TOKEN, "");
        return token == null ? "" : token;
    }

    public static void setToken(Context context, String token) {
        prefs(context).edit().putString(KEY_TOKEN, token == null ? "" : token).apply();
    }

    /**
     * 确保存在一个令牌，没有则生成并保存。
     */
    public static String ensureToken(Context context) {
        String token = getToken(context);
        if (token.isEmpty()) {
            token = randomToken();
            setToken(context, token);
        }
        return token;
    }

    public static String randomToken() {
        String hex = "0123456789abcdef";
        StringBuilder sb = new StringBuilder(32);
        java.util.Random random = new java.util.Random(System.nanoTime());
        for (int i = 0; i < 32; i++) {
            sb.append(hex.charAt(random.nextInt(16)));
        }
        return sb.toString();
    }

    public static String getLastClient(Context context) {
        return prefs(context).getString(KEY_LAST_CLIENT, "");
    }

    public static void setLastClient(Context context, String client) {
        prefs(context).edit().putString(KEY_LAST_CLIENT, client).apply();
    }

    /**
     * 取局域网 IPv4 地址，取不到时返回 127.0.0.1。
     */
    public static String localIpAddress() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            String fallback = null;
            for (NetworkInterface ni : interfaces) {
                if (ni.isLoopback() || !ni.isUp()) {
                    continue;
                }
                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress() || addr.isLinkLocalAddress()) {
                        continue;
                    }
                    String host = addr.getHostAddress();
                    if (host == null) {
                        continue;
                    }
                    String name = ni.getName();
                    if (name != null && (name.startsWith("wlan") || name.startsWith("ap"))) {
                        return host;
                    }
                    if (fallback == null) {
                        fallback = host;
                    }
                }
            }
            if (fallback != null) {
                return fallback;
            }
        } catch (Exception ignored) {
            // 权限或环境限制，退化为回环地址
        }
        return "127.0.0.1";
    }
}

package com.example.anative.mcp;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/**
 * MCP 服务运行日志（内存环形缓冲，供设置页展示）。
 */
public final class McpLog {

    private static final String TAG = "McpServer";
    private static final int MAX_LINES = 300;
    private static final ArrayDeque<String> LINES = new ArrayDeque<>();
    private static final SimpleDateFormat TIME_FORMAT =
            new SimpleDateFormat("HH:mm:ss", Locale.US);

    private McpLog() {
    }

    public static void info(String message) {
        add("INFO", message);
    }

    public static void warn(String message) {
        add("WARN", message);
    }

    public static void error(String message) {
        add("ERR ", message);
    }

    private static void add(String level, String message) {
        String line;
        synchronized (TIME_FORMAT) {
            line = TIME_FORMAT.format(new Date()) + "  " + level + "  " + message;
        }
        synchronized (LINES) {
            LINES.addLast(line);
            while (LINES.size() > MAX_LINES) {
                LINES.removeFirst();
            }
        }
        if ("ERR ".equals(level)) {
            Log.e(TAG, message);
        } else {
            Log.i(TAG, message);
        }
    }

    public static String dump() {
        StringBuilder sb = new StringBuilder();
        synchronized (LINES) {
            for (String line : LINES) {
                sb.append(line).append('\n');
            }
        }
        if (sb.length() == 0) {
            return "暂无日志\n";
        }
        return sb.toString();
    }

    public static void clear() {
        synchronized (LINES) {
            LINES.clear();
        }
    }
}

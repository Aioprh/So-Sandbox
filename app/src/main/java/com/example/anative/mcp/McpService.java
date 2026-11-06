package com.example.anative.mcp;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.example.anative.R;
import com.example.anative.ui.McpActivity;

/**
 * 前台服务：保证 MCP 服务在 App 退到后台后仍可被客户端访问。
 */
public class McpService extends Service {

    public static final String ACTION_START = "com.example.anative.mcp.START";
    public static final String ACTION_STOP = "com.example.anative.mcp.STOP";

    private static final String CHANNEL_ID = "mcp_service";
    private static final int NOTIFICATION_ID = 2001;

    @Override
    public void onCreate() {
        super.onCreate();
        createChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            McpManager.stop(this);
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, buildNotification("正在启动…"));

        try {
            McpManager.start(this);
            updateNotification(buildNotification(describe()));
        } catch (Exception e) {
            McpLog.error("MCP 服务启动失败: " + e.getMessage());
            updateNotification(buildNotification("启动失败: " + e.getMessage()));
            McpPrefs.setEnabled(this, false);
        }
        return START_STICKY;
    }

    private String describe() {
        int port = McpManager.getPort();
        if (port <= 0) {
            return "未运行";
        }
        return "监听 " + McpPrefs.localIpAddress() + ":" + port + " · " + McpManager.getToolCount() + " 个工具";
    }

    private Notification buildNotification(String text) {
        Intent intent = new Intent(this, McpActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int pendingFlag = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                ? PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
                : PendingIntent.FLAG_UPDATE_CURRENT;
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, pendingFlag);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("SoSandbox MCP 服务")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_connect)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setOngoing(true)
                .setContentIntent(pendingIntent)
                .build();
    }

    private void updateNotification(Notification notification) {
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification);
        }
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "MCP 服务", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("保持 MCP 服务在后台运行");
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);
    }

    @Override
    public void onDestroy() {
        McpManager.stop(this);
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}

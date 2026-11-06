package com.example.anative.mcp;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * 极简 HTTP 服务器，实现两种 MCP 传输：
 *
 * - Streamable HTTP: POST /mcp（JSON-RPC，单次请求-响应）
 * - HTTP + SSE(旧版): GET /sse 建立事件流，POST /messages?sessionId=xxx 发送消息
 *
 * 不依赖任何第三方库，直接基于 ServerSocket 实现。
 */
public class McpServer {

    private static final int MAX_BODY_BYTES = 4 * 1024 * 1024;
    private static final int MAX_HEADER_BYTES = 32 * 1024;

    private final Context context;
    private final McpProtocol protocol;
    private final Map<String, SseSession> sseSessions = new ConcurrentHashMap<>();

    private ServerSocket serverSocket;
    private Thread acceptThread;
    private ExecutorService workerPool;
    private volatile boolean running;
    private volatile int port;
    private volatile String token = "";
    private String sessionId = "";

    public McpServer(Context context) {
        this.context = context.getApplicationContext();
        this.protocol = new McpProtocol(this.context);
    }

    public boolean isRunning() {
        return running;
    }

    public int getPort() {
        return port;
    }

    public int getToolCount() {
        return protocol.toolCount();
    }

    public synchronized void start(int port, String token) throws IOException {
        if (running) {
            return;
        }
        this.token = token == null ? "" : token.trim();
        this.sessionId = UUID.randomUUID().toString();

        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(port));
        serverSocket = socket;
        this.port = port;
        running = true;

        workerPool = Executors.newCachedThreadPool();
        acceptThread = new Thread(this::acceptLoop, "mcp-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();

        McpLog.info("MCP 服务已启动: http://" + McpPrefs.localIpAddress() + ":" + port + "/mcp"
                + (this.token.isEmpty() ? "（未启用令牌）" : "（需要令牌）"));
    }

    public synchronized void stop() {
        if (!running && serverSocket == null) {
            return;
        }
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
            // 关闭失败无影响
        }
        serverSocket = null;

        for (SseSession session : sseSessions.values()) {
            session.close();
        }
        sseSessions.clear();

        if (workerPool != null) {
            workerPool.shutdownNow();
            workerPool = null;
        }
        McpLog.info("MCP 服务已停止");
    }

    // ==================== 接入循环 ====================

    private void acceptLoop() {
        while (running) {
            try {
                final Socket socket = serverSocket.accept();
                ExecutorService pool = workerPool;
                if (pool == null) {
                    socket.close();
                    break;
                }
                pool.execute(() -> handleConnection(socket));
            } catch (SocketException e) {
                if (running) {
                    McpLog.warn("accept 异常: " + e.getMessage());
                }
                break;
            } catch (IOException e) {
                if (running) {
                    McpLog.warn("accept 异常: " + e.getMessage());
                }
            }
        }
    }

    private void handleConnection(Socket socket) {
        String remote = String.valueOf(socket.getRemoteSocketAddress());
        try {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(30000);
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isEmpty()) {
                closeQuietly(socket);
                return;
            }
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                closeQuietly(socket);
                return;
            }
            String method = parts[0].toUpperCase(Locale.US);
            String target = parts[1];

            String path = target;
            String query = "";
            int queryIndex = target.indexOf('?');
            if (queryIndex >= 0) {
                path = target.substring(0, queryIndex);
                query = target.substring(queryIndex + 1);
            }

            Map<String, String> headers = readHeaders(in);

            if ("OPTIONS".equals(method)) {
                writeResponse(out, 204, "text/plain; charset=utf-8", new byte[0]);
                closeQuietly(socket);
                return;
            }

            if ("/sse".equals(path) && "GET".equals(method)) {
                if (!authorized(headers, query)) {
                    writeJson(out, 401, "{\"error\":\"unauthorized\"}");
                    closeQuietly(socket);
                    return;
                }
                serveSse(socket, in, out);
                return;
            }

            byte[] body = readBody(in, headers);
            String bodyText = new String(body, StandardCharsets.UTF_8);

            if (!path.startsWith("/health") && !"/".equals(path) && !authorized(headers, query)) {
                McpLog.warn("拒绝未授权请求: " + remote + " " + path);
                writeJson(out, 401, "{\"error\":\"unauthorized\",\"hint\":\"请带上 Authorization: Bearer <令牌>\"}");
                closeQuietly(socket);
                return;
            }

            if ("/".equals(path) && "GET".equals(method)) {
                writeHtml(out, infoPage());
                closeQuietly(socket);
                return;
            }

            if ("/health".equals(path)) {
                writeJson(out, 200, "{\"status\":\"ok\",\"server\":\"" + McpTools.SERVER_NAME
                        + "\",\"version\":\"" + McpTools.SERVER_VERSION + "\"}");
                closeQuietly(socket);
                return;
            }

            if ("/tools".equals(path)) {
                writeJson(out, 200, protocolToolsJson());
                closeQuietly(socket);
                return;
            }

            if ("/mcp".equals(path)) {
                if (!"POST".equals(method)) {
                    writeJson(out, 405, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,"
                            + "\"message\":\"Use POST /mcp for JSON-RPC, or GET /sse for the legacy SSE transport\"}}");
                    closeQuietly(socket);
                    return;
                }
                if (bodyText.trim().isEmpty()) {
                    writeJson(out, 400, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,"
                            + "\"message\":\"Empty body\"}}");
                    closeQuietly(socket);
                    return;
                }
                McpLog.info("MCP 请求: " + summarize(bodyText));
                String response = protocol.handle(bodyText);
                if (response == null) {
                    writeResponse(out, 202, "application/json; charset=utf-8", new byte[0]);
                } else {
                    writeJson(out, 200, response);
                }
                closeQuietly(socket);
                return;
            }

            if ("/messages".equals(path)) {
                if (!"POST".equals(method)) {
                    writeJson(out, 405, "{\"error\":\"method not allowed\"}");
                    closeQuietly(socket);
                    return;
                }
                String sid = queryParam(query, "sessionId");
                SseSession session = sid == null ? null : sseSessions.get(sid);
                if (session == null) {
                    writeJson(out, 404, "{\"error\":\"session not found\"}");
                    closeQuietly(socket);
                    return;
                }
                McpLog.info("MCP(SSE) 请求: " + summarize(bodyText));
                String response = protocol.handle(bodyText);
                if (response != null) {
                    session.send("event: message\ndata: " + response + "\n\n");
                }
                writeResponse(out, 202, "text/plain; charset=utf-8", new byte[0]);
                closeQuietly(socket);
                return;
            }

            writeJson(out, 404, "{\"error\":\"not found\",\"path\":\"" + path + "\"}");
            closeQuietly(socket);
        } catch (SocketException e) {
            McpLog.warn("连接中断: " + remote + " " + e.getMessage());
            closeQuietly(socket);
        } catch (Exception e) {
            McpLog.error("处理请求失败(" + remote + "): " + e);
            closeQuietly(socket);
        }
    }

    // ==================== SSE ====================

    private void serveSse(Socket socket, InputStream in, OutputStream out) throws IOException {
        String sid = UUID.randomUUID().toString();
        SseSession session = new SseSession(sid, socket, out);
        sseSessions.put(sid, session);
        McpLog.info("MCP SSE 会话建立: " + sid);

        try {
            String head = "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: text/event-stream; charset=utf-8\r\n"
                    + "Cache-Control: no-cache, no-transform\r\n"
                    + "Connection: keep-alive\r\n"
                    + "Access-Control-Allow-Origin: *\r\n"
                    + "\r\n";
            out.write(head.getBytes(StandardCharsets.UTF_8));
            session.send("event: endpoint\ndata: /messages?sessionId=" + sid + "\n\n");
            out.flush();

            while (running && !socket.isClosed() && !session.isClosed()) {
                String event = session.poll(15, TimeUnit.SECONDS);
                if (event == null) {
                    session.send(": keep-alive\n\n");
                } else {
                    session.send(event);
                }
            }
        } catch (Exception e) {
            McpLog.warn("SSE 会话结束: " + sid + " (" + e.getMessage() + ")");
        } finally {
            sseSessions.remove(sid);
            session.close();
            closeQuietly(socket);
        }
    }

    private static class SseSession {
        private final String id;
        private final Socket socket;
        private final OutputStream out;
        private final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>();
        private volatile boolean closed;

        SseSession(String id, Socket socket, OutputStream out) {
            this.id = id;
            this.socket = socket;
            this.out = out;
            try {
                socket.setSoTimeout(0);
            } catch (SocketException ignored) {
                // 忽略
            }
        }

        boolean isClosed() {
            return closed || socket.isClosed();
        }

        synchronized void send(String data) {
            if (closed) {
                return;
            }
            try {
                out.write(data.getBytes(StandardCharsets.UTF_8));
                out.flush();
            } catch (IOException e) {
                closed = true;
            }
        }

        String poll(long timeout, TimeUnit unit) throws InterruptedException {
            return queue.poll(timeout, unit);
        }

        void close() {
            closed = true;
            closeQuietly(socket);
        }
    }

    // ==================== HTTP 工具 ====================

    private boolean authorized(Map<String, String> headers, String query) {
        if (token.isEmpty() || !McpPrefs.isAuthRequired(context)) {
            return true;
        }
        String header = headers.get("authorization");
        if (header != null) {
            String value = header.trim();
            if (value.toLowerCase(Locale.US).startsWith("bearer ")) {
                value = value.substring(7).trim();
            }
            if (constantTimeEquals(token, value)) {
                return true;
            }
        }
        String alt = headers.get("x-mcp-token");
        if (alt != null && constantTimeEquals(token, alt.trim())) {
            return true;
        }
        String param = queryParam(query, "token");
        return param != null && constantTimeEquals(token, param);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    private static String queryParam(String query, String key) {
        if (query == null || query.isEmpty()) {
            return null;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = pair.substring(0, eq);
            if (!name.equals(key)) {
                continue;
            }
            try {
                return java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
            } catch (Exception e) {
                return pair.substring(eq + 1);
            }
        }
        return null;
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                buffer.write(b);
            }
            if (buffer.size() > MAX_HEADER_BYTES) {
                throw new IOException("header too large");
            }
        }
        if (b == -1 && buffer.size() == 0) {
            return null;
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private static Map<String, String> readHeaders(InputStream in) throws IOException {
        Map<String, String> headers = new HashMap<>();
        int total = 0;
        while (true) {
            String line = readLine(in);
            if (line == null || line.isEmpty()) {
                break;
            }
            total += line.length();
            if (total > MAX_HEADER_BYTES) {
                throw new IOException("headers too large");
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String name = line.substring(0, colon).trim().toLowerCase(Locale.US);
            String value = line.substring(colon + 1).trim();
            headers.put(name, value);
        }
        return headers;
    }

    private static byte[] readBody(InputStream in, Map<String, String> headers) throws IOException {
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase(Locale.US).contains("chunked")) {
            return readChunked(in);
        }
        String contentLength = headers.get("content-length");
        int length = 0;
        if (contentLength != null) {
            try {
                length = Integer.parseInt(contentLength.trim());
            } catch (NumberFormatException e) {
                length = 0;
            }
        }
        if (length <= 0) {
            return new byte[0];
        }
        if (length > MAX_BODY_BYTES) {
            throw new IOException("body too large");
        }
        byte[] body = new byte[length];
        int read = 0;
        while (read < length) {
            int n = in.read(body, read, length - read);
            if (n < 0) {
                break;
            }
            read += n;
        }
        if (read < length) {
            byte[] truncated = new byte[read];
            System.arraycopy(body, 0, truncated, 0, read);
            return truncated;
        }
        return body;
    }

    private static byte[] readChunked(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                break;
            }
            int semicolon = sizeLine.indexOf(';');
            if (semicolon >= 0) {
                sizeLine = sizeLine.substring(0, semicolon);
            }
            int size;
            try {
                size = Integer.parseInt(sizeLine.trim(), 16);
            } catch (NumberFormatException e) {
                break;
            }
            if (size == 0) {
                readLine(in);
                break;
            }
            byte[] chunk = new byte[size];
            int read = 0;
            while (read < size) {
                int n = in.read(chunk, read, size - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
            out.write(chunk, 0, read);
            if (out.size() > MAX_BODY_BYTES) {
                throw new IOException("body too large");
            }
            readLine(in);
        }
        return out.toByteArray();
    }

    private void writeJson(OutputStream out, int code, String json) throws IOException {
        writeResponse(out, code, "application/json; charset=utf-8", json.getBytes(StandardCharsets.UTF_8));
    }

    private void writeHtml(OutputStream out, String html) throws IOException {
        writeResponse(out, 200, "text/html; charset=utf-8", html.getBytes(StandardCharsets.UTF_8));
    }

    private void writeResponse(OutputStream out, int code, String contentType, byte[] body) throws IOException {
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(code).append(' ').append(reason(code)).append("\r\n");
        head.append("Content-Type: ").append(contentType).append("\r\n");
        head.append("Content-Length: ").append(body.length).append("\r\n");
        head.append("Connection: close\r\n");
        head.append("Access-Control-Allow-Origin: *\r\n");
        head.append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
        head.append("Access-Control-Allow-Headers: Content-Type, Authorization, Mcp-Session-Id, "
                + "MCP-Protocol-Version, Accept, Last-Event-ID, X-Mcp-Token\r\n");
        head.append("Access-Control-Expose-Headers: Mcp-Session-Id\r\n");
        if (!sessionId.isEmpty()) {
            head.append("Mcp-Session-Id: ").append(sessionId).append("\r\n");
        }
        head.append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.UTF_8));
        if (body.length > 0) {
            out.write(body);
        }
        out.flush();
    }

    private static String reason(int code) {
        switch (code) {
            case 200:
                return "OK";
            case 202:
                return "Accepted";
            case 204:
                return "No Content";
            case 400:
                return "Bad Request";
            case 401:
                return "Unauthorized";
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 500:
                return "Internal Server Error";
            default:
                return "Unknown";
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ignored) {
            // 忽略
        }
    }

    private String protocolToolsJson() {
        try {
            return new org.json.JSONObject()
                    .put("server", McpTools.SERVER_NAME)
                    .put("version", McpTools.SERVER_VERSION)
                    .put("tools", protocol.toolDefinitions())
                    .toString();
        } catch (Exception e) {
            return "{\"error\":\"tools unavailable\"}";
        }
    }

    private static String summarize(String body) {
        String flat = body.replace('\n', ' ').replace('\r', ' ');
        if (flat.length() > 160) {
            return flat.substring(0, 160) + "...";
        }
        return flat;
    }

    private String infoPage() {
        String ip = McpPrefs.localIpAddress();
        int toolCount = protocol.toolCount();
        return "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>SoSandbox MCP</title><style>"
                + "body{font-family:-apple-system,Roboto,sans-serif;background:#12141a;color:#e6e8ee;"
                + "margin:0;padding:24px;line-height:1.6}h1{font-size:20px;margin:0 0 4px}"
                + ".muted{color:#8b93a7;font-size:13px}code{background:#1c1f28;padding:2px 6px;"
                + "border-radius:6px;font-size:13px;word-break:break-all}.card{background:#181b22;"
                + "border-radius:12px;padding:16px;margin-top:16px}"
                + "li{margin:6px 0}</style></head><body>"
                + "<h1>SoSandbox MCP Server</h1>"
                + "<div class=\"muted\">版本 " + McpTools.SERVER_VERSION + " · " + toolCount + " 个工具</div>"
                + "<div class=\"card\"><div>Streamable HTTP</div><code>http://" + ip + ":" + port + "/mcp</code>"
                + "<div style=\"margin-top:12px\">旧版 SSE</div><code>http://" + ip + ":" + port + "/sse</code></div>"
                + "<div class=\"card\"><div>客户端配置示例（Claude Desktop / Cursor 等）</div><pre><code>"
                + "{ \"mcpServers\": { \"so-sandbox\": { \"type\": \"http\", \"url\": \"http://" + ip + ":"
                + port + "/mcp\", \"headers\": { \"Authorization\": \"Bearer &lt;你的令牌&gt;\" } } } }"
                + "</code></pre></div>"
                + "<div class=\"card\"><div>可用工具</div><ul>"
                + "<li>so_status / so_open</li>"
                + "<li>so_list_functions / so_disassemble / so_decompile / so_read_hex</li>"
                + "<li>so_search_strings / so_list_plt / so_list_sections / so_xrefs</li>"
                + "<li>so_write_asm / so_write_hex / so_save / so_recognize_function</li>"
                + "</ul></div></body></html>";
    }
}

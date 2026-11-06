package com.example.anative.mcp;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Locale;

/**
 * MCP 协议层：JSON-RPC 2.0 消息分发。
 *
 * 支持 Streamable HTTP（POST /mcp）与旧版 HTTP+SSE（GET /sse + POST /messages）两种传输，
 * 协议版本在 initialize 时协商。
 */
public class McpProtocol {

    public static final String DEFAULT_PROTOCOL_VERSION = "2025-06-18";
    private static final String[] SUPPORTED_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"};

    private static final String INSTRUCTIONS =
            "这是 SoSandbox（Android 上的 ARM64 SO 逆向分析工具）的 MCP 接口。\n"
                    + "典型流程：\n"
                    + "1. so_open 打开一个 SO 文件（绝对路径，仅支持 ARM64）；\n"
                    + "2. so_list_functions / so_search_strings / so_list_plt 浏览结构；\n"
                    + "3. so_disassemble / so_decompile / so_read_hex / so_xrefs 分析具体函数；\n"
                    + "4. 需要改包时用 so_write_asm / so_write_hex，最后 so_save 另存新文件。\n"
                    + "所有地址都是 ELF 虚拟地址（与函数列表中的偏移一致），支持 0x 前缀。\n"
                    + "修改会写入 App 私有工作副本，原始文件不会被改动。";

    private final Context context;
    private final McpTools tools;

    public McpProtocol(Context context) {
        this.context = context.getApplicationContext();
        this.tools = new McpTools(this.context);
    }

    public int toolCount() {
        try {
            return tools.listTools().length();
        } catch (JSONException e) {
            return 0;
        }
    }

    public JSONArray toolDefinitions() throws JSONException {
        return tools.listTools();
    }

    /**
     * 处理一条（或一批）JSON-RPC 消息。
     *
     * @return 响应 JSON 文本；若全部是通知则返回 null。
     */
    public String handle(String body) {
        String trimmed = body == null ? "" : body.trim();
        if (trimmed.isEmpty()) {
            return errorResponse(null, -32700, "Parse error: empty body");
        }
        try {
            if (trimmed.startsWith("[")) {
                JSONArray batch = new JSONArray(trimmed);
                JSONArray responses = new JSONArray();
                for (int i = 0; i < batch.length(); i++) {
                    JSONObject request = batch.optJSONObject(i);
                    if (request == null) {
                        continue;
                    }
                    JSONObject response = handleOne(request);
                    if (response != null) {
                        responses.put(response);
                    }
                }
                return responses.length() == 0 ? null : responses.toString();
            }
            JSONObject request = new JSONObject(trimmed);
            JSONObject response = handleOne(request);
            return response == null ? null : response.toString();
        } catch (JSONException e) {
            return errorResponse(null, -32700, "Parse error: " + e.getMessage());
        }
    }

    private JSONObject handleOne(JSONObject request) {
        Object id = request.has("id") ? request.opt("id") : null;
        String method = request.optString("method", "");
        JSONObject params = request.optJSONObject("params");
        if (params == null) {
            params = new JSONObject();
        }

        if (method.isEmpty()) {
            return errorObject(id, -32600, "Invalid Request: missing method");
        }

        // 通知（没有 id）不需要响应
        boolean isNotification = !request.has("id");

        try {
            switch (method) {
                case "initialize":
                    return result(id, initializeResult(params));
                case "notifications/initialized":
                case "notifications/cancelled":
                case "notifications/roots/list_changed":
                case "notifications/progress":
                    return null;
                case "ping":
                    return result(id, new JSONObject());
                case "tools/list":
                    return result(id, new JSONObject().put("tools", tools.listTools()));
                case "tools/call": {
                    String name = params.optString("name", "");
                    JSONObject arguments = params.optJSONObject("arguments");
                    if (name.isEmpty()) {
                        return errorObject(id, -32602, "Invalid params: missing tool name");
                    }
                    return result(id, tools.call(name, arguments));
                }
                case "resources/list":
                    return result(id, new JSONObject().put("resources", new JSONArray()));
                case "resources/templates/list":
                    return result(id, new JSONObject().put("resourceTemplates", new JSONArray()));
                case "prompts/list":
                    return result(id, new JSONObject().put("prompts", new JSONArray()));
                case "logging/setLevel":
                    return result(id, new JSONObject());
                case "completion/complete":
                    return result(id, new JSONObject().put("completion",
                            new JSONObject().put("values", new JSONArray()).put("total", 0).put("hasMore", false)));
                default:
                    return errorObject(id, -32601, "Method not found: " + method);
            }
        } catch (JSONException e) {
            return errorObject(id, -32603, "Internal error: " + e.getMessage());
        } catch (Throwable t) {
            McpLog.error("处理 " + method + " 失败: " + t);
            if (isNotification) {
                return null;
            }
            return errorObject(id, -32603, "Internal error: " + t.getMessage());
        }
    }

    private JSONObject initializeResult(JSONObject params) throws JSONException {
        String requested = params.optString("protocolVersion", "");
        String negotiated = DEFAULT_PROTOCOL_VERSION;
        for (String version : SUPPORTED_VERSIONS) {
            if (version.equals(requested)) {
                negotiated = version;
                break;
            }
        }

        JSONObject clientInfo = params.optJSONObject("clientInfo");
        if (clientInfo != null) {
            String name = clientInfo.optString("name", "unknown");
            String version = clientInfo.optString("version", "");
            McpPrefs.setLastClient(context, (name + " " + version).trim());
            McpLog.info("MCP 客户端接入: " + name + " " + version);
        }

        JSONObject capabilities = new JSONObject();
        capabilities.put("tools", new JSONObject().put("listChanged", false));
        capabilities.put("logging", new JSONObject());

        JSONObject serverInfo = new JSONObject();
        serverInfo.put("name", McpTools.SERVER_NAME);
        serverInfo.put("title", "SoSandbox");
        serverInfo.put("version", McpTools.SERVER_VERSION);

        return new JSONObject()
                .put("protocolVersion", negotiated)
                .put("capabilities", capabilities)
                .put("serverInfo", serverInfo)
                .put("instructions", INSTRUCTIONS);
    }

    private static JSONObject result(Object id, JSONObject result) {
        JSONObject response = new JSONObject();
        try {
            response.put("jsonrpc", "2.0");
            response.put("id", id == null ? JSONObject.NULL : id);
            response.put("result", result);
        } catch (JSONException e) {
            McpLog.error("构造响应失败: " + e.getMessage());
        }
        return response;
    }

    private static JSONObject errorObject(Object id, int code, String message) {
        JSONObject response = new JSONObject();
        try {
            JSONObject error = new JSONObject();
            error.put("code", code);
            error.put("message", message);
            response.put("jsonrpc", "2.0");
            response.put("id", id == null ? JSONObject.NULL : id);
            response.put("error", error);
        } catch (JSONException e) {
            McpLog.error("构造错误响应失败: " + e.getMessage());
        }
        return response;
    }

    private static String errorResponse(Object id, int code, String message) {
        return errorObject(id, code, message).toString();
    }
}

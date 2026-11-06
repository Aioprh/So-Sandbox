# SoSandbox MCP 服务

SoSandbox 内置了一个 MCP（Model Context Protocol）服务器，把 App 的 SO 分析能力暴露给任意支持 MCP 的 AI 客户端（Claude Desktop、Cursor、Cherry Studio、Claude Code 等）。

开启后，AI 可以自己打开 SO、列函数、反汇编、反编译、查字符串/PLT/交叉引用，甚至改指令并另存文件——整个过程都在手机上完成，SO 不需要上传到任何服务器。

---

## 1. 快速开始

1. 手机打开 SoSandbox → 右上角菜单 → **设置** → **MCP 服务**
2. 打开「启用 MCP 服务」开关（会启动一个前台服务，通知栏出现常驻通知）
3. 页面顶部会显示连接地址，例如：

   ```
   http://192.168.1.20:8765/mcp
   ```

4. 点击「客户端配置」复制 JSON，粘贴到你的 MCP 客户端里
5. 手机和电脑必须在**同一个局域网**（同一 WiFi）

> 端口默认 `8765`，可在页面里改；令牌默认自动生成，可在「访问令牌」里复制/重置/关闭校验。

---

## 2. 客户端配置

### 通用（Streamable HTTP）

```json
{
  "mcpServers": {
    "so-sandbox": {
      "type": "http",
      "url": "http://192.168.1.20:8765/mcp",
      "headers": {
        "Authorization": "Bearer <你的令牌>"
      }
    }
  }
}
```

### Claude Desktop / Cursor（`claude_desktop_config.json` 或 `mcp.json`）

同上，部分客户端把 `type` 写成 `"streamable-http"`，语义一致。

### 旧版 SSE 客户端

如果客户端只支持 HTTP+SSE 传输，把地址换成：

```
http://192.168.1.20:8765/sse
```

服务端会返回 `event: endpoint`，后续消息自动走 `/messages?sessionId=...`。

### Claude Code

```bash
claude mcp add --transport http so-sandbox http://192.168.1.20:8765/mcp \
  --header "Authorization: Bearer <你的令牌>"
```

### 自检

浏览器直接打开 `http://<手机IP>:8765/` 可以看到服务信息页；`/health` 返回 `{"status":"ok"}`，`/tools` 返回工具清单 JSON。

---

## 3. 工具清单

| 工具 | 作用 | 关键参数 |
| --- | --- | --- |
| `so_status` | 当前 SO 状态（路径、大小、模式、数量、未保存修改） | — |
| `so_open` | 按绝对路径打开 ARM64 SO，解析函数/字符串/PLT | `path`、`discovery_mode`、`load_strings` |
| `so_list_functions` | 列函数，支持关键字过滤与分页 | `query`、`limit`、`cursor` |
| `so_disassemble` | ARM64 汇编（带字符串/PLT/函数名注释） | `function` 或 `offset`、`max_bytes` |
| `so_decompile` | 本地伪 C 反编译 | `function` 或 `offset` |
| `so_read_hex` | 读取原始字节 + ASCII 对照 | `offset`、`size` |
| `so_search_strings` | 搜索字符串表 | `query`、`limit`、`filter_noise`、`section` |
| `so_string_refs` | 哪些函数引用了某个字符串 | `address` 或 `string`、`limit` |
| `so_xrefs` | 交叉引用（调用方/被调用方） | `function` 或 `offset`、`direction` |
| `so_list_plt` | PLT 跳转表 | `query`、`limit` |
| `so_list_sections` | 节表（类型/标志/地址/大小） | — |
| `so_write_asm` | 改写汇编指令（可 `dry_run` 预演） | `offset`、`assembly`、`dry_run` |
| `so_write_hex` | 改写字节 | `offset`、`hex` |
| `so_search_bytes` | 特征码/字节搜索（支持 ??） | `pattern`、`offset`、`size`、`limit` |
| `so_patch_batch` | 批量修改，失败自动回滚 | `patches`、`dry_run` |
| `so_diff` | 查看修改差异与撤销状态 | 无 |
| `so_export_report` | 导出 Markdown 分析报告 | `output`、`top_functions`、`string_samples` |
| `so_save` | 另存修改后的 SO | `output` |
| `so_recognize_function` | 把地址登记为函数（符号被剥离时） | `offset`、`size` |

要点：

- **所有地址都是 ELF 虚拟地址**（与 App 函数列表里的偏移一致），支持 `0x1234` 或十进制字符串。
- `function` 支持精确名、demangle 名与唯一子串匹配；重名时会要求改用 `offset`。
- 修改类工具写入的是 App 私有工作副本，**原始 SO 不会被改动**；需要落地时调用 `so_save`。
- 可在 App 的 MCP 页面开启「只读模式」，开启后 `so_write_asm`、`so_write_hex`、`so_patch_batch` 会被拒绝。
- 每次写入都会记录为补丁，可用 `so_diff` 查看，或在「设置 → 修改记录」里逐条撤销/重做。

---

## 4. 典型对话

> 「打开 /sdcard/Download/libnative.so，找一下名字里带 verify 的函数，反汇编看看它做了什么」

AI 会依次调用：

```
so_open        { "path": "/sdcard/Download/libnative.so" }
so_list_functions { "query": "verify", "limit": 20 }
so_disassemble { "function": "Java_com_example_verify" }
```

> 「把 0x1A2C 处的 mov x0, #0 改成 mov x0, #1，然后另存」

```
so_write_asm { "offset": "0x1A2C", "assembly": "mov x0, #1" }
so_save      {}
```

---

## 5. 协议与实现细节

- JSON-RPC 2.0，支持批量请求；协议版本在 `initialize` 协商（`2025-06-18` / `2025-03-26` / `2024-11-05`）
- 能力：`tools`（19 个工具）、`logging`；`resources/list`、`prompts/list` 返回空列表
- 传输：
  - `POST /mcp` → Streamable HTTP，单次请求-响应（`Content-Type: application/json`）
  - `GET /sse` + `POST /messages?sessionId=` → 旧版 HTTP+SSE
- 鉴权：`Authorization: Bearer <token>`，也接受 `X-Mcp-Token` 头或 `?token=`（用于不支持自定义头的客户端）
- 零依赖：HTTP 服务基于 `ServerSocket` 手写，不引入任何第三方库

源码位置：

```
app/src/main/java/com/example/anative/mcp/
├── McpServer.java    # HTTP 服务 + 双传输
├── McpProtocol.java  # JSON-RPC 分发、initialize 协商
├── McpTools.java     # 19 个工具的实现
├── McpManager.java   # 生命周期（单例）
├── McpService.java   # 前台服务，保证后台可访问
├── McpPrefs.java     # 端口/令牌/开关
└── McpLog.java       # 运行日志（设置页可见）
app/src/main/java/com/example/anative/ui/McpActivity.java
app/src/main/res/layout/activity_mcp.xml
```

---

## 6. 安全建议

- 默认开启令牌校验，且令牌随每次安装随机生成；**不要关闭**除非你完全信任当前网络。
- 服务只监听局域网，不做外网穿透；如需远程使用，请自行走 VPN / 内网穿透并保留令牌。
- 写入类工具会真实修改工作副本，建议让 AI 先在 `dry_run` 下验证汇编，再执行写入。
- 敏感样本分析完毕后，关闭开关即可立即停止服务。

---

## 7. 已知限制

- 仅支持 ARM64（aarch64）SO；32 位与 x86_64 会被拒绝。
- MCP 侧固定为**静态分析模式**（不 dlopen 目标 SO），因此不提供动态调用/JNI_OnLoad 类工具。
- `so_xrefs` 首次扫描大库（如 libil2cpp.so）可能需要数秒。
- 前台服务被系统回收后，回到 App 的 MCP 页面重新打开开关即可恢复。

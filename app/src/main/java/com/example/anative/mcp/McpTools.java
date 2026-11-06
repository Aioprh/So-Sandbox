package com.example.anative.mcp;

import android.content.Context;
import android.os.Environment;

import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PatchManager;
import com.example.anative.core.PltEntry;
import com.example.anative.core.XRefScanner;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * MCP 工具集：把 SoSandbox 的 SO 分析能力暴露给 AI 客户端。
 *
 * 所有 offset 均为 ELF 虚拟地址（即符号表 st_value / 文件内偏移语义，与 App 内函数列表一致）。
 */
public class McpTools {

    public static final String SERVER_NAME = "so-sandbox";
    public static final String SERVER_VERSION = "1.8.0";

    private static final int MAX_TEXT_OUTPUT = 120000;
    private static final int MAX_TABLE_STRINGS = 40000;

    private final Context context;

    /** 反汇编注释表缓存，避免每次调用都重建（大库可达数十万条）。 */
    private String tableCachePath;
    private String cachedStringTable = "";
    private String cachedPltTable = "";
    private String cachedFuncTable = "";

    public McpTools(Context context) {
        this.context = context.getApplicationContext();
    }

    // ==================== 工具定义 ====================

    public JSONArray listTools() throws JSONException {
        JSONArray tools = new JSONArray();

        tools.put(tool("so_status", "查看当前 SO 状态",
                "返回当前已加载 SO 的路径、大小、基址、模式、函数/字符串/PLT 数量以及未保存修改数。",
                schema()));

        tools.put(tool("so_open", "打开 SO 文件",
                "按绝对路径打开并解析一个 ARM64 SO：解析函数表、字符串表、PLT。文件只会被复制/读取，不会改动原文件。",
                schema(
                        "path", prop("string", "SO 文件绝对路径，例如 /sdcard/Download/libxxx.so"),
                        "discovery_mode", enumProp(new String[]{"precise", "balanced", "max_coverage"},
                                "函数发现方式，默认 balanced"),
                        "load_strings", prop("boolean", "是否同时解析字符串表（默认 true）")
                ).put("required", new JSONArray().put("path"))));

        tools.put(tool("so_list_functions", "列出函数",
                "列出函数（名称、虚拟地址、大小、来源）。支持按名称/地址关键字过滤与分页。",
                schema(
                        "query", prop("string", "按函数名（含 demangle 名）或地址模糊过滤"),
                        "limit", prop("integer", "返回条数上限，默认 100，最大 1000"),
                        "cursor", prop("integer", "分页起始下标，默认 0")
                )));

        tools.put(tool("so_disassemble", "反汇编函数",
                "输出指定函数的 ARM64 汇编（带字符串/PLT/函数名注释）。function 与 offset 二者取一。",
                schema(
                        "function", prop("string", "函数名，可传导出名或 demangle 名"),
                        "offset", offsetProp("函数虚拟地址，支持 0x1234 或十进制"),
                        "max_bytes", prop("integer", "最多反汇编字节数，默认函数大小，上限 65536")
                )));

        tools.put(tool("so_decompile", "伪 C 反编译",
                "输出指定函数的本地伪 C 代码（与 App 内本地伪 C 一致，不调用 AI）。",
                schema(
                        "function", prop("string", "函数名"),
                        "offset", offsetProp("函数虚拟地址")
                )));

        tools.put(tool("so_read_hex", "读取十六进制",
                "从文件读取指定虚拟地址开始的原始字节（含 ASCII 对照）。只读，不修改文件。",
                schema(
                        "offset", offsetProp("起始虚拟地址"),
                        "size", prop("integer", "读取字节数，默认 128，上限 4096")
                ).put("required", new JSONArray().put("offset"))));

        tools.put(tool("so_search_strings", "搜索字符串",
                "在已解析的字符串表中搜索（不区分大小写）。query 为空时返回前 limit 条。",
                schema(
                        "query", prop("string", "关键字"),
                        "limit", prop("integer", "返回条数，默认 50，最大 500"),
                        "filter_noise", prop("boolean", "过滤 .dynstr/.strtab 与 _Z 等噪声字符串"),
                        "section", prop("string", "仅返回指定节，如 .rodata")
                )));

        tools.put(tool("so_xrefs", "交叉引用分析",
                "扫描 .text 段，返回函数的调用方/被调用方。首次扫描大库可能需要数秒。",
                schema(
                        "function", prop("string", "函数名"),
                        "offset", offsetProp("函数虚拟地址"),
                        "direction", enumProp(new String[]{"both", "callers", "callees"}, "方向，默认 both"),
                        "limit", prop("integer", "每个方向最多返回条数，默认 100")
                )));

        tools.put(tool("so_string_refs", "查询字符串引用",
                "找出哪些函数引用了某个字符串（按地址或文本匹配）。首次扫描大库可能需要数秒。",
                schema(
                        "address", offsetProp("字符串虚拟地址"),
                        "string", prop("string", "字符串内容（精确匹配优先，其次包含匹配）"),
                        "limit", prop("integer", "最多返回条数，默认 100")
                )));

        tools.put(tool("so_list_plt", "列出 PLT",
                "列出 PLT 跳转表条目（导入函数名 + 虚拟地址），可按名称过滤。",
                schema(
                        "query", prop("string", "按符号名过滤"),
                        "limit", prop("integer", "返回条数，默认 200")
                )));

        tools.put(tool("so_list_sections", "列出节表",
                "列出 ELF 节表（索引、名称、类型、标志、虚拟地址、文件偏移、大小）。",
                schema()));

        tools.put(tool("so_write_asm", "修改汇编指令",
                "把指定地址的指令改写为新的 ARM64 汇编（会真实写入当前工作副本，可用 dry_run 先验证）。",
                schema(
                        "offset", offsetProp("指令虚拟地址"),
                        "assembly", prop("string", "新的 ARM64 汇编，例如 \"mov x0, #0\""),
                        "dry_run", prop("boolean", "仅验证汇编是否合法并返回机器码，不写入")
                ).put("required", new JSONArray().put("offset").put("assembly"))));

        tools.put(tool("so_write_hex", "修改字节",
                "把指定地址开始的字节改写为给定十六进制串（会真实写入当前工作副本）。",
                schema(
                        "offset", offsetProp("起始虚拟地址"),
                        "hex", prop("string", "十六进制字节串，可含空格，例如 \"1f 20 03 d5\"")
                ).put("required", new JSONArray().put("offset").put("hex"))));

        tools.put(tool("so_search_bytes", "按字节特征搜索",
                "在文件中搜索字节序列，支持 ?? 通配（如 \"1F 20 03 D5\" 或 \"1f??03d5\"）。返回命中处的虚拟地址与上下文。",
                schema(
                        "pattern", prop("string", "字节特征，空格可选，?? 表示通配"),
                        "offset", offsetProp("可选起始虚拟地址"),
                        "size", prop("integer", "可选扫描字节数，默认扫描到文件末尾"),
                        "limit", prop("integer", "最多返回条数，默认 20，上限 200")
                ).put("required", new JSONArray().put("pattern"))));

        tools.put(tool("so_patch_batch", "批量修改",
                "一次提交多条修改，任一条失败会自动回滚本批次已写入的补丁。每条可用 hex 或 assembly 指定。",
                schema(
                        "patches", prop("array", "数组，元素形如 {\"offset\":\"0x1234\",\"hex\":\"1f 20 03 d5\"} 或 {\"offset\":..., \"assembly\":\"nop\"}"),
                        "dry_run", prop("boolean", "只校验不写入，默认 false")
                ).put("required", new JSONArray().put("patches"))));

        tools.put(tool("so_diff", "查看修改差异",
                "列出当前会话的所有补丁（原字节 / 新字节 / 是否已撤销），可用于保存前确认。",
                schema()));

        tools.put(tool("so_export_report", "导出分析报告",
                "生成 Markdown 分析报告（文件信息、函数与字符串概要、补丁差异），默认保存到 /sdcard/SoSandbox。",
                schema(
                        "output", prop("string", "可选输出路径"),
                        "top_functions", prop("integer", "按大小列出的函数数量，默认 30"),
                        "string_samples", prop("integer", "字符串样例数量，默认 50")
                )));

        tools.put(tool("so_save", "保存修改后的 SO",
                "把当前工作副本（含所有修改）另存为新文件，默认保存到 /sdcard/SoSandbox/<原名>_saved.so。",
                schema(
                        "output", prop("string", "可选输出绝对路径；不传则使用默认目录")
                )));

        tools.put(tool("so_recognize_function", "识别地址为函数",
                "把一个可执行段内的地址登记为函数（用于符号被剥离的 SO），并返回其反汇编长度。",
                schema(
                        "offset", offsetProp("要识别的地址"),
                        "size", prop("integer", "可选函数大小，不传则自动估算")
                ).put("required", new JSONArray().put("offset"))));

        return tools;
    }

    // ==================== 工具调度 ====================

    /**
     * 执行工具，返回 MCP 的 tools/call result。
     */
    public synchronized JSONObject call(String name, JSONObject args) {
        try {
            JSONObject arguments = args == null ? new JSONObject() : args;
            switch (name) {
                case "so_status":
                    return text(status());
                case "so_open":
                    return text(open(arguments));
                case "so_list_functions":
                    return text(listFunctions(arguments));
                case "so_disassemble":
                    return text(disassemble(arguments));
                case "so_decompile":
                    return text(decompile(arguments));
                case "so_read_hex":
                    return text(readHex(arguments));
                case "so_search_strings":
                    return text(searchStrings(arguments));
                case "so_xrefs":
                    return text(xrefs(arguments));
                case "so_list_plt":
                    return text(listPlt(arguments));
                case "so_string_refs":
                    return text(stringRefs(arguments));
                case "so_list_sections":
                    return text(listSections());
                case "so_write_asm":
                    return text(writeAsm(arguments));
                case "so_write_hex":
                    return text(writeHex(arguments));
                case "so_search_bytes":
                    return text(searchBytes(arguments));
                case "so_patch_batch":
                    return text(patchBatch(arguments));
                case "so_diff":
                    return text(PatchManager.getInstance().diff());
                case "so_export_report":
                    return text(exportReport(arguments));
                case "so_save":
                    return text(save(arguments));
                case "so_recognize_function":
                    return text(recognize(arguments));
                default:
                    return error("未知工具: " + name);
            }
        } catch (ToolException e) {
            return error(e.getMessage());
        } catch (Throwable t) {
            McpLog.error("工具 " + name + " 执行异常: " + t);
            return error("执行失败: " + (t.getMessage() == null ? t.toString() : t.getMessage()));
        }
    }

    // ==================== 工具实现 ====================

    private String status() throws ToolException {
        DataHolder holder = DataHolder.getInstance();
        String path = holder.getSoPath();
        StringBuilder sb = new StringBuilder();
        sb.append("SoSandbox MCP ").append(SERVER_VERSION).append('\n');
        if (path == null || path.isEmpty()) {
            sb.append("SO 状态: 未加载\n");
            sb.append("提示: 调用 so_open 传入 SO 绝对路径开始分析。\n");
            return sb.toString();
        }
        File file = new File(path);
        long base = holder.getBaseAddress();
        sb.append("SO 路径: ").append(path).append('\n');
        sb.append("文件大小: ").append(file.exists() ? file.length() : -1).append(" 字节\n");
        sb.append("基址: ").append(base > 0 ? String.format(Locale.US, "0x%X", base) : "静态分析(0)")
                .append('\n');
        sb.append("模式: ").append(base > 0 ? "动态加载" : "静态分析").append('\n');
        List<NativeFunction> functions = holder.getFunctions();
        sb.append("函数数: ").append(functions == null ? 0 : functions.size()).append('\n');
        List<ElfParser.StringEntry> strings = holder.getStrings();
        sb.append("字符串数: ").append(strings == null ? 0 : strings.size()).append('\n');
        List<PltEntry> plt = holder.getPltEntries();
        sb.append("PLT 条目: ").append(plt == null ? 0 : plt.size()).append('\n');
        sb.append("未保存修改: ").append(holder.hasUnsavedChanges() ? "是" : "否")
                .append("（指令修改 ").append(holder.getModifiedCount()).append(" 条）\n");
        sb.append("补丁记录: ").append(PatchManager.getInstance().getTotalCount())
                .append(" 条，生效 ").append(PatchManager.getInstance().getActiveCount()).append(" 条\n");
        if (McpPrefs.isReadOnly(context)) {
            sb.append("模式: 只读（写入类工具已禁用）\n");
        }
        return sb.toString();
    }

    private String open(JSONObject args) throws Exception {
        String path = optString(args, "path");
        if (path == null || path.isEmpty()) {
            throw new ToolException("缺少参数 path");
        }
        File file = new File(path);
        if (!file.exists() || !file.isFile()) {
            throw new ToolException("文件不存在: " + path);
        }
        if (file.length() < 64) {
            throw new ToolException("文件过小，不是有效的 ELF: " + path);
        }
        checkElfArch(file);

        String mode = optString(args, "discovery_mode");
        if (mode == null || mode.isEmpty()) {
            mode = "balanced";
        }
        boolean loadStrings = !args.has("load_strings") || args.optBoolean("load_strings", true);

        DataHolder holder = DataHolder.getInstance();
        holder.setSoPath(path);
        holder.setOriginalUri(null);
        holder.setBaseAddress(0);
        holder.setDlopenHandle(0);

        List<NativeFunction> functions = ElfParser.parseFunctions(path, mode);
        holder.setFunctions(functions);

        List<ElfParser.StringEntry> strings = new ArrayList<>();
        if (loadStrings) {
            try {
                strings = ElfParser.parseStrings(path);
            } catch (Exception e) {
                McpLog.warn("解析字符串失败: " + e.getMessage());
            }
        }
        holder.setStrings(strings);

        List<PltEntry> plt = new ArrayList<>();
        try {
            plt = ElfParser.parsePlt(path);
        } catch (Exception e) {
            McpLog.warn("解析 PLT 失败: " + e.getMessage());
        }
        holder.setPltEntries(plt);

        tableCachePath = null;
        McpLog.info("MCP 打开 SO: " + path + " (" + functions.size() + " 函数)");

        StringBuilder sb = new StringBuilder();
        sb.append("已打开: ").append(path).append('\n');
        sb.append("文件大小: ").append(file.length()).append(" 字节\n");
        sb.append("架构: ARM64\n");
        sb.append("函数发现方式: ").append(mode).append('\n');
        sb.append("函数数: ").append(functions.size()).append('\n');
        sb.append("字符串数: ").append(strings.size()).append('\n');
        sb.append("PLT 条目: ").append(plt.size()).append('\n');
        sb.append("工作副本: 修改会写入 App 私有副本，原文件不变；so_save 可另存结果。\n");
        return sb.toString();
    }

    private String listFunctions(JSONObject args) throws ToolException {
        List<NativeFunction> functions = requireFunctions();
        String query = optString(args, "query");
        String needle = query == null ? null : query.toLowerCase(Locale.US).trim();
        int limit = clamp(args.optInt("limit", 100), 1, 1000);
        int cursor = Math.max(0, args.optInt("cursor", 0));

        List<NativeFunction> matched = new ArrayList<>();
        for (NativeFunction f : functions) {
            if (needle != null && !needle.isEmpty()) {
                String name = f.getName() == null ? "" : f.getName().toLowerCase(Locale.US);
                String demangled = f.getDemangledName() == null ? "" : f.getDemangledName().toLowerCase(Locale.US);
                String addr = String.format(Locale.US, "%x", f.getOffset());
                if (!name.contains(needle) && !demangled.contains(needle) && !addr.contains(needle)) {
                    continue;
                }
            }
            matched.add(f);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("匹配 ").append(matched.size()).append(" 个函数");
        if (needle != null && !needle.isEmpty()) {
            sb.append("（关键字: ").append(query).append("）");
        }
        sb.append('\n');
        int end = Math.min(matched.size(), cursor + limit);
        for (int i = cursor; i < end; i++) {
            NativeFunction f = matched.get(i);
            sb.append('[').append(i).append("] 0x")
                    .append(String.format(Locale.US, "%X", f.getOffset()))
                    .append("  size=").append(f.getSize());
            if (f.getSource() != null && !f.getSource().isEmpty()) {
                sb.append("  ").append(f.getSource());
            }
            sb.append("  ").append(f.getName());
            String demangled = f.getDemangledName();
            if (demangled != null && !demangled.equals(f.getName())) {
                sb.append("  (").append(demangled).append(')');
            }
            sb.append('\n');
        }
        if (end < matched.size()) {
            sb.append("还有 ").append(matched.size() - end)
                    .append(" 条，使用 cursor=").append(end).append(" 继续。\n");
        }
        return sb.toString();
    }

    private String disassemble(JSONObject args) throws Exception {
        NativeFunction function = resolveFunction(args);
        long size = resolveFunctionSize(function, args.optInt("max_bytes", 0));
        long virtualOffset = toVirtualLong(function.getOffset());
        long fileOffset = ElfParser.virtualAddrToFileOffset(requirePath(), virtualOffset);
        byte[] bytes = readBytes(fileOffset, (int) size);

        String stringTable = tables()[0];
        String pltTable = tables()[1];
        String funcTable = tables()[2];

        String code = NativeInvoker.disassembleBytes(bytes, virtualOffset, size, stringTable, pltTable, funcTable);
        if (code == null || code.isEmpty()) {
            throw new ToolException("反汇编失败（原生引擎无输出）");
        }
        if (code.startsWith("ERR")) {
            long base = DataHolder.getInstance().getBaseAddress();
            if (base > 0) {
                String fallback = NativeInvoker.disassembleFunctionEx(
                        base + virtualOffset, size, stringTable, pltTable, base, funcTable);
                if (fallback != null && !fallback.isEmpty() && !fallback.startsWith("ERR")) {
                    code = fallback;
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("函数: ").append(function.getDemangledName()).append('\n');
        sb.append("地址: 0x").append(String.format(Locale.US, "%X", virtualOffset))
                .append("  大小: ").append(size).append(" 字节\n\n");
        sb.append(code);
        return limit(sb.toString());
    }

    private String decompile(JSONObject args) throws Exception {
        NativeFunction function = resolveFunction(args);
        long size = resolveFunctionSize(function, 0);
        long virtualOffset = toVirtualLong(function.getOffset());
        long fileOffset = ElfParser.virtualAddrToFileOffset(requirePath(), virtualOffset);
        byte[] bytes = readBytes(fileOffset, (int) size);

        String code = NativeInvoker.decompileBytes(bytes, virtualOffset, size,
                function.getDemangledName(), function.getNativeSignature());
        if (code == null || code.isEmpty()) {
            throw new ToolException("伪 C 反编译失败（原生引擎无输出）");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("函数: ").append(function.getDemangledName()).append('\n');
        sb.append("地址: 0x").append(String.format(Locale.US, "%X", virtualOffset))
                .append("  大小: ").append(size).append(" 字节\n\n");
        sb.append(code);
        return limit(sb.toString());
    }

    private String readHex(JSONObject args) throws Exception {
        long virtualOffset = requireOffset(args, "offset");
        int size = clamp(args.optInt("size", 128), 1, 4096);
        if (DataHolder.getInstance().getSoPath() == null) {
            throw new ToolException("尚未加载 SO，请先调用 so_open");
        }
        long fileOffset = ElfParser.virtualAddrToFileOffset(requirePath(), virtualOffset);
        byte[] bytes = readBytes(fileOffset, size);
        return hexDump(virtualOffset, bytes);
    }

    private String searchStrings(JSONObject args) throws ToolException {
        List<ElfParser.StringEntry> strings = DataHolder.getInstance().getStrings();
        if (strings == null || strings.isEmpty()) {
            throw new ToolException("字符串表为空，请先调用 so_open（load_strings=true）");
        }
        String query = optString(args, "query");
        String needle = query == null ? "" : query.toLowerCase(Locale.US);
        boolean filterNoise = args.optBoolean("filter_noise", false);
        String section = optString(args, "section");
        int limit = clamp(args.optInt("limit", 50), 1, 500);

        StringBuilder sb = new StringBuilder();
        int shown = 0;
        int matched = 0;
        for (ElfParser.StringEntry e : strings) {
            if (e == null || e.value == null) {
                continue;
            }
            if (section != null && !section.isEmpty() && !section.equals(e.section)) {
                continue;
            }
            if (filterNoise && isNoisy(e)) {
                continue;
            }
            if (!needle.isEmpty() && !e.value.toLowerCase(Locale.US).contains(needle)) {
                continue;
            }
            matched++;
            if (shown < limit) {
                sb.append("0x").append(String.format(Locale.US, "%X", e.virtualAddress))
                        .append("  [").append(e.section == null ? "?" : e.section).append("]  ")
                        .append(e.value)
                        .append('\n');
                shown++;
            }
        }
        if (matched == 0) {
            return "未找到匹配字符串" + (needle.isEmpty() ? "" : "（关键字: " + query + "）") + "\n";
        }
        StringBuilder head = new StringBuilder();
        head.append("匹配 ").append(matched).append(" 条，显示 ").append(shown).append(" 条\n");
        return head.append(sb).toString();
    }

    private String xrefs(JSONObject args) throws Exception {
        NativeFunction function = resolveFunction(args);
        long funcOffset = toVirtualLong(function.getOffset());
        String direction = optString(args, "direction");
        if (direction == null) {
            direction = "both";
        }
        int limit = clamp(args.optInt("limit", 100), 1, 500);

        DataHolder holder = DataHolder.getInstance();
        XRefScanner scanner = holder.getXRefScanner();
        if (scanner == null || !scanner.isScanned()) {
            scanner = new XRefScanner();
            scanner.scan(requirePath(), holder.getFunctions(), holder.getStrings());
            holder.setXRefScanner(scanner);
        }

        Map<Long, String> names = new HashMap<>();
        List<NativeFunction> functions = holder.getFunctions();
        if (functions != null) {
            for (NativeFunction f : functions) {
                names.put(toVirtualLong(f.getOffset()), f.getDemangledName());
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("函数: ").append(function.getDemangledName())
                .append("  地址: 0x").append(String.format(Locale.US, "%X", funcOffset)).append('\n');

        if ("both".equals(direction) || "callers".equals(direction)) {
            List<XRefScanner.CallRef> callers = scanner.getCallersOf(funcOffset);
            sb.append("\n被调用（callers）: ").append(callers == null ? 0 : callers.size()).append(" 处\n");
            if (callers != null) {
                for (int i = 0; i < Math.min(callers.size(), limit); i++) {
                    XRefScanner.CallRef ref = callers.get(i);
                    sb.append("  0x").append(String.format(Locale.US, "%X", ref.instrOffset))
                            .append("  <- ").append(nameOf(names, ref.callerFuncOffset))
                            .append(" @0x").append(String.format(Locale.US, "%X", ref.callerFuncOffset))
                            .append('\n');
                }
                if (callers.size() > limit) {
                    sb.append("  ... 省略 ").append(callers.size() - limit).append(" 条\n");
                }
            }
        }

        if ("both".equals(direction) || "callees".equals(direction)) {
            List<XRefScanner.CallRef> callees = scanner.getCalleesOf(funcOffset);
            sb.append("\n调用了（callees）: ").append(callees == null ? 0 : callees.size()).append(" 处\n");
            if (callees != null) {
                for (int i = 0; i < Math.min(callees.size(), limit); i++) {
                    XRefScanner.CallRef ref = callees.get(i);
                    sb.append("  0x").append(String.format(Locale.US, "%X", ref.instrOffset))
                            .append("  -> ").append(ref.callerFuncName == null
                                    ? nameOf(names, ref.callerFuncOffset) : ref.callerFuncName)
                            .append(" @0x").append(String.format(Locale.US, "%X", ref.callerFuncOffset))
                            .append('\n');
                }
                if (callees.size() > limit) {
                    sb.append("  ... 省略 ").append(callees.size() - limit).append(" 条\n");
                }
            }
        }
        return sb.toString();
    }

    private String stringRefs(JSONObject args) throws Exception {
        List<ElfParser.StringEntry> strings = DataHolder.getInstance().getStrings();
        if (strings == null || strings.isEmpty()) {
            throw new ToolException("字符串表为空，请先调用 so_open（load_strings=true）");
        }
        String text = optString(args, "string");
        long address = -1;
        if (args.has("address") && !args.isNull("address")) {
            address = requireOffset(args, "address");
        }

        if (address < 0) {
            if (text == null || text.isEmpty()) {
                throw new ToolException("需要提供 address 或 string");
            }
            for (ElfParser.StringEntry e : strings) {
                if (e != null && text.equals(e.value)) {
                    address = e.virtualAddress;
                    break;
                }
            }
            if (address < 0) {
                StringBuilder candidates = new StringBuilder();
                int found = 0;
                for (ElfParser.StringEntry e : strings) {
                    if (e == null || e.value == null || !e.value.contains(text)) {
                        continue;
                    }
                    if (found < 10) {
                        candidates.append("  0x").append(String.format(Locale.US, "%X", e.virtualAddress))
                                .append("  ").append(e.value).append('\n');
                    }
                    found++;
                }
                if (found == 0) {
                    throw new ToolException("未找到字符串: " + text);
                }
                throw new ToolException("字符串不唯一（" + found + " 条匹配），请用 address 指定。候选:\n"
                        + candidates);
            }
        }

        DataHolder holder = DataHolder.getInstance();
        XRefScanner scanner = holder.getXRefScanner();
        if (scanner == null || !scanner.isScanned()) {
            scanner = new XRefScanner();
            scanner.scan(requirePath(), holder.getFunctions(), strings);
            holder.setXRefScanner(scanner);
        }

        int limit = clamp(args.optInt("limit", 100), 1, 500);
        List<XRefScanner.StringRef> refs = scanner.getStringRefsAt(address);
        StringBuilder sb = new StringBuilder();
        sb.append("字符串: 0x").append(String.format(Locale.US, "%X", address)).append('\n');
        if (text != null && !text.isEmpty()) {
            sb.append("内容: ").append(text).append('\n');
        }
        sb.append("引用函数: ").append(refs == null ? 0 : refs.size()).append(" 处\n");
        if (refs != null) {
            for (int i = 0; i < Math.min(refs.size(), limit); i++) {
                XRefScanner.StringRef ref = refs.get(i);
                sb.append("  ").append(ref.funcName)
                        .append(" @0x").append(String.format(Locale.US, "%X", ref.funcOffset))
                        .append("  引用指令 0x").append(String.format(Locale.US, "%X", ref.instrOffset))
                        .append('\n');
            }
            if (refs.size() > limit) {
                sb.append("  ... 省略 ").append(refs.size() - limit).append(" 条\n");
            }
        }
        return sb.toString();
    }

    private String listPlt(JSONObject args) throws ToolException {
        List<PltEntry> entries = DataHolder.getInstance().getPltEntries();
        if (entries == null || entries.isEmpty()) {
            throw new ToolException("PLT 表为空，请先调用 so_open");
        }
        String needle = optString(args, "query");
        String lower = needle == null ? "" : needle.toLowerCase(Locale.US);
        int limit = clamp(args.optInt("limit", 200), 1, 2000);

        StringBuilder sb = new StringBuilder();
        int shown = 0;
        for (PltEntry e : entries) {
            if (e == null) {
                continue;
            }
            if (!lower.isEmpty() && (e.symbolName == null || !e.symbolName.toLowerCase(Locale.US).contains(lower))) {
                continue;
            }
            if (shown >= limit) {
                sb.append("... 结果已截断\n");
                break;
            }
            sb.append("0x").append(String.format(Locale.US, "%X", e.offset))
                    .append("  size=").append(e.size)
                    .append("  got=0x").append(String.format(Locale.US, "%X", e.gotOffset))
                    .append("  ").append(e.symbolName)
                    .append('\n');
            shown++;
        }
        if (shown == 0) {
            return "未找到匹配的 PLT 条目\n";
        }
        return "PLT 条目: " + entries.size() + " 个，显示 " + shown + " 个\n" + sb;
    }

    private String listSections() throws Exception {
        List<ElfParser.SectionInfo> sections = ElfParser.parseSections(requirePath());
        StringBuilder sb = new StringBuilder();
        sb.append("节表共 ").append(sections.size()).append(" 项\n");
        for (ElfParser.SectionInfo s : sections) {
            sb.append(String.format(Locale.US, "[%02d] %-18s %-14s %-6s va=0x%08X off=0x%08X size=0x%X",
                    s.index, safe(s.name), safe(s.getTypeName()), safe(s.getFlagsString()),
                    s.virtualAddress, s.offset, s.size));
            if (s.entSize > 0) {
                sb.append(" entsize=").append(s.entSize);
            }
            sb.append('\n');
        }
        return limit(sb.toString());
    }

    private String writeAsm(JSONObject args) throws Exception {
        long virtualOffset = requireOffset(args, "offset");
        String assembly = optString(args, "assembly");
        if (assembly == null || assembly.trim().isEmpty()) {
            throw new ToolException("缺少参数 assembly");
        }
        String path = requirePath();
        boolean dryRun = args.optBoolean("dry_run", false);

        byte[] encoded = NativeInvoker.assembleInstruction(assembly, virtualOffset);
        if (encoded == null || encoded.length == 0) {
            String err = NativeInvoker.getLastAssembleError();
            throw new ToolException("汇编失败" + (err == null || err.isEmpty() ? "" : ": " + err));
        }

        StringBuilder sb = new StringBuilder();
        sb.append("地址: 0x").append(String.format(Locale.US, "%X", virtualOffset)).append('\n');
        sb.append("汇编: ").append(assembly).append('\n');
        sb.append("机器码: ").append(toHex(encoded)).append('\n');

        if (dryRun) {
            sb.append("dry_run=true，未写入文件。\n");
            return sb.toString();
        }

        requireWritable();
        // 自己算文件偏移再写，避免原生 patchInstruction 里 vaddr==fileOffset 的简化假设
        long fileOffset = ElfParser.virtualAddrToFileOffset(path, virtualOffset);
        try {
            PatchManager.getInstance().apply(path, fileOffset, encoded,
                    PatchManager.Kind.ASM, "汇编: " + assembly, virtualOffset);
        } catch (IOException e) {
            throw new ToolException("写入失败: " + e.getMessage());
        }
        int written = encoded.length;
        DataHolder.getInstance().putModifiedInstruction(virtualOffset, assembly);
        DataHolder.getInstance().markFileModified();
        McpLog.info("MCP 修改指令 @0x" + String.format(Locale.US, "%X", virtualOffset) + " -> " + assembly);

        sb.append("已写入 ").append(written).append(" 字节（工作副本）。\n");
        sb.append("提示: 调用 so_save 另存修改后的文件。\n");
        return sb.toString();
    }

    private String writeHex(JSONObject args) throws Exception {
        long virtualOffset = requireOffset(args, "offset");
        String hex = optString(args, "hex");
        if (hex == null) {
            throw new ToolException("缺少参数 hex");
        }
        byte[] bytes = parseHex(hex);
        if (bytes.length == 0) {
            throw new ToolException("hex 参数为空或格式非法");
        }
        String path = requirePath();
        requireWritable();
        long fileOffset = ElfParser.virtualAddrToFileOffset(path, virtualOffset);

        try {
            PatchManager.getInstance().apply(path, fileOffset, bytes,
                    PatchManager.Kind.HEX, "字节: " + toHex(bytes), virtualOffset);
        } catch (IOException e) {
            throw new ToolException("写入失败: " + e.getMessage());
        }
        McpLog.info("MCP 修改字节 @0x" + String.format(Locale.US, "%X", virtualOffset)
                + " 长度 " + bytes.length);

        return "已写入 " + bytes.length + " 字节 @0x"
                + String.format(Locale.US, "%X", virtualOffset) + "（工作副本）\n"
                + "数据: " + toHex(bytes) + "\n"
                + "提示: 调用 so_save 另存修改后的文件。\n";
    }

    private String save(JSONObject args) throws Exception {
        String path = requirePath();
        File src = new File(path);
        if (!src.exists()) {
            throw new ToolException("工作副本不存在: " + path);
        }
        String output = optString(args, "output");
        File dest;
        if (output != null && !output.isEmpty()) {
            dest = new File(output);
        } else {
            String name = src.getName();
            String newName = name.endsWith(".so")
                    ? name.substring(0, name.length() - 3) + "_saved.so"
                    : name + "_saved";
            File dir = new File(Environment.getExternalStorageDirectory(), "SoSandbox");
            if (!dir.exists() && !dir.mkdirs()) {
                dir = context.getExternalFilesDir(null);
            }
            dest = new File(dir, newName);
        }

        File parent = dest.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new ToolException("无法创建输出目录: " + parent);
        }

        try (FileInputStream fis = new FileInputStream(src);
             FileOutputStream fos = new FileOutputStream(dest)) {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
            fos.getFD().sync();
        }
        DataHolder.getInstance().clearUnsavedChanges();
        McpLog.info("MCP 保存 SO -> " + dest.getAbsolutePath());

        return "已保存: " + dest.getAbsolutePath() + "\n大小: " + dest.length() + " 字节\n";
    }

    private String recognize(JSONObject args) throws Exception {
        long virtualOffset = requireOffset(args, "offset");
        long size = args.optLong("size", 0);
        List<NativeFunction> functions = requireFunctions();
        for (NativeFunction f : functions) {
            if (toVirtualLong(f.getOffset()) == virtualOffset) {
                return "该地址已在函数表中: " + f.getDemangledName() + "\n";
            }
        }
        if (size <= 0) {
            size = 256;
        }
        NativeFunction function = new NativeFunction(
                "sub_" + String.format(Locale.US, "%X", virtualOffset), virtualOffset, size, "manual");
        functions.add(function);
        DataHolder.getInstance().setFunctions(functions);
        tableCachePath = null;
        McpLog.info("MCP 手动识别函数 @0x" + String.format(Locale.US, "%X", virtualOffset));
        return "已登记函数: " + function.getName() + "  地址: 0x"
                + String.format(Locale.US, "%X", virtualOffset) + "  大小: " + size + "\n";
    }

    // ==================== 内部工具 ====================

    private String searchBytes(JSONObject args) throws Exception {
        String path = requirePath();
        String patternText = optString(args, "pattern");
        if (patternText == null || patternText.trim().isEmpty()) {
            throw new ToolException("缺少参数 pattern");
        }
        String compact = patternText.replace(" ", "").replace("-", "").trim();
        if (compact.isEmpty() || compact.length() % 2 != 0) {
            throw new ToolException("pattern 需为偶数个十六进制字符，例如 1F 20 03 D5 或 1f??03d5");
        }
        int patternLength = compact.length() / 2;
        byte[] pattern = new byte[patternLength];
        boolean[] mask = new boolean[patternLength];
        for (int i = 0; i < patternLength; i++) {
            String pair = compact.substring(i * 2, i * 2 + 2);
            if (pair.equals("??") || pair.equals("**")) {
                mask[i] = false;
            } else {
                try {
                    pattern[i] = (byte) Integer.parseInt(pair, 16);
                } catch (NumberFormatException e) {
                    throw new ToolException("非法字节: " + pair);
                }
                mask[i] = true;
            }
        }
        if (patternLength == 0) {
            throw new ToolException("pattern 为空");
        }

        long startVa = 0;
        if (args.has("offset") && !args.isNull("offset")) {
            startVa = requireOffset(args, "offset");
        }
        long startFile = startVa > 0 ? ElfParser.virtualAddrToFileOffset(path, startVa) : 0;
        long size = args.optLong("size", 0);
        int limit = clamp(args.optInt("limit", 20), 1, 200);

        File file = new File(path);
        long end = size > 0 ? Math.min(file.length(), startFile + size) : file.length();
        if (startFile >= end) {
            throw new ToolException("扫描范围为空");
        }

        List<ElfParser.SectionInfo> sections = ElfParser.parseSections(path);
        StringBuilder sb = new StringBuilder();
        int found = 0;
        long lastMatch = -1;
        int chunkSize = 1 << 20;
        byte[] buffer = new byte[chunkSize + patternLength];

        try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
            long pos = startFile;
            outer:
            while (pos < end) {
                int toRead = (int) Math.min(buffer.length, end - pos);
                raf.seek(pos);
                raf.readFully(buffer, 0, toRead);
                int lastStart = toRead - patternLength;
                for (int i = 0; i <= lastStart; i++) {
                    boolean matched = true;
                    for (int k = 0; k < patternLength; k++) {
                        if (mask[k] && buffer[i + k] != pattern[k]) {
                            matched = false;
                            break;
                        }
                    }
                    if (!matched) {
                        continue;
                    }
                    long fileOffset = pos + i;
                    if (fileOffset <= lastMatch) {
                        continue;
                    }
                    lastMatch = fileOffset;
                    long va = mapToVirtual(sections, fileOffset);
                    int ctxStart = Math.max(0, i - 8);
                    int ctxEnd = Math.min(toRead, i + patternLength + 8);
                    sb.append(String.format(Locale.US, "0x%X  (off 0x%X)  ", va, fileOffset));
                    for (int k = ctxStart; k < ctxEnd; k++) {
                        sb.append(String.format(Locale.US, "%02X ", buffer[k] & 0xFF));
                    }
                    sb.append('\n');
                    found++;
                    if (found >= limit) {
                        break outer;
                    }
                }
                if (toRead < buffer.length) {
                    break;
                }
                pos += toRead - (patternLength - 1);
            }
        }

        if (found == 0) {
            return "未找到匹配: " + patternText;
        }
        StringBuilder head = new StringBuilder();
        head.append("匹配 ").append(found).append(" 处");
        if (found >= limit) {
            head.append("（结果已截断，可增大 limit）");
        }
        head.append('\n');
        return head + sb.toString();
    }

    private static long mapToVirtual(List<ElfParser.SectionInfo> sections, long fileOffset) {
        for (ElfParser.SectionInfo section : sections) {
            if (section.size > 0 && fileOffset >= section.offset
                    && fileOffset < section.offset + section.size && section.virtualAddress > 0) {
                return section.virtualAddress + (fileOffset - section.offset);
            }
        }
        return fileOffset;
    }

    private String patchBatch(JSONObject args) throws Exception {
        String path = requirePath();
        JSONArray patches = args.optJSONArray("patches");
        if (patches == null || patches.length() == 0) {
            throw new ToolException("缺少参数 patches（非空数组）");
        }
        boolean dryRun = args.optBoolean("dry_run", false);
        if (!dryRun) {
            requireWritable();
        }

        List<Integer> applied = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        sb.append(dryRun ? "批量校验（dry_run，不写入）\n" : "批量修改\n");

        for (int i = 0; i < patches.length(); i++) {
            JSONObject item = patches.getJSONObject(i);
            long virtualAddress = requireOffset(item, "offset");
            String hex = optString(item, "hex");
            String assembly = optString(item, "assembly");

            byte[] bytes;
            String description;
            if (hex != null && !hex.trim().isEmpty()) {
                bytes = parseHex(hex);
                description = "字节: " + toHex(bytes);
            } else if (assembly != null && !assembly.trim().isEmpty()) {
                bytes = NativeInvoker.assembleInstruction(assembly, virtualAddress);
                if (bytes == null || bytes.length == 0) {
                    String err = NativeInvoker.getLastAssembleError();
                    throw new ToolException("第 " + (i + 1) + " 条汇编失败"
                            + (err == null || err.isEmpty() ? "" : ": " + err));
                }
                description = "汇编: " + assembly;
            } else {
                throw new ToolException("第 " + (i + 1) + " 条缺少 hex 或 assembly");
            }
            if (bytes.length == 0) {
                throw new ToolException("第 " + (i + 1) + " 条数据为空");
            }

            if (dryRun) {
                sb.append(String.format(Locale.US, "  #%d 0x%X  %s  OK\n",
                        i + 1, virtualAddress, toHex(bytes)));
                continue;
            }

            try {
                long fileOffset = ElfParser.virtualAddrToFileOffset(path, virtualAddress);
                PatchManager.Patch patch = PatchManager.getInstance().apply(path, fileOffset, bytes,
                        PatchManager.Kind.BATCH, "批量 #" + (i + 1) + " " + description, virtualAddress);
                applied.add(patch.id);
                sb.append(String.format(Locale.US, "  #%d 0x%X  %s  已写入\n",
                        i + 1, virtualAddress, toHex(bytes)));
            } catch (Exception e) {
                int rolledBack = 0;
                for (int id : applied) {
                    try {
                        if (PatchManager.getInstance().undo(id)) {
                            rolledBack++;
                        }
                    } catch (IOException ignored) {
                        // 继续回滚其余条目
                    }
                }
                throw new ToolException("第 " + (i + 1) + " 条失败，已回滚 "
                        + rolledBack + " 条: " + e.getMessage());
            }
        }

        if (!dryRun) {
            sb.append("共写入 ").append(applied.size()).append(" 条，可用 so_diff 查看。\n");
        }
        return sb.toString();
    }

    private String exportReport(JSONObject args) throws Exception {
        String path = requirePath();
        DataHolder holder = DataHolder.getInstance();
        int topFunctions = clamp(args.optInt("top_functions", 30), 1, 200);
        int stringSamples = clamp(args.optInt("string_samples", 50), 0, 500);

        StringBuilder md = new StringBuilder();
        md.append("# SoSandbox 分析报告\n\n");
        md.append("- 文件: `").append(path).append("`\n");
        File file = new File(path);
        md.append("- 大小: ").append(file.length()).append(" 字节\n");
        md.append("- 基址: ").append(holder.getBaseAddress() > 0
                ? String.format(Locale.US, "0x%X", holder.getBaseAddress()) : "静态分析(0)").append('\n');
        md.append("- 函数: ").append(holder.getFunctions() == null ? 0 : holder.getFunctions().size()).append('\n');
        md.append("- 字符串: ").append(holder.getStrings() == null ? 0 : holder.getStrings().size()).append('\n');
        md.append("- PLT: ").append(holder.getPltEntries() == null ? 0 : holder.getPltEntries().size()).append("\n\n");

        md.append("## 节表\n\n| # | 名称 | 类型 | 虚拟地址 | 文件偏移 | 大小 |\n|---|---|---|---|---|---|\n");
        for (ElfParser.SectionInfo section : ElfParser.parseSections(path)) {
            md.append(String.format(Locale.US, "| %d | %s | %s | 0x%X | 0x%X | 0x%X |\n",
                    section.index, safe(section.name), safe(section.getTypeName()),
                    section.virtualAddress, section.offset, section.size));
        }

        List<NativeFunction> functions = holder.getFunctions();
        if (functions != null && !functions.isEmpty()) {
            List<NativeFunction> sorted = new ArrayList<>(functions);
            sorted.sort((a, b) -> Long.compare(b.getSize(), a.getSize()));
            md.append("\n## 最大的函数（Top ").append(Math.min(topFunctions, sorted.size())).append("）\n\n");
            md.append("| 地址 | 大小 | 名称 |\n|---|---|---|\n");
            for (int i = 0; i < Math.min(topFunctions, sorted.size()); i++) {
                NativeFunction function = sorted.get(i);
                md.append(String.format(Locale.US, "| 0x%X | %d | %s |\n",
                        function.getOffset(), function.getSize(), safe(function.getDemangledName())));
            }
        }

        List<ElfParser.StringEntry> strings = holder.getStrings();
        if (strings != null && stringSamples > 0) {
            md.append("\n## 字符串样例\n\n```\n");
            int count = 0;
            for (ElfParser.StringEntry entry : strings) {
                if (entry == null || entry.value == null || entry.value.isEmpty() || isNoisy(entry)) {
                    continue;
                }
                md.append(String.format(Locale.US, "0x%X  %s\n", entry.virtualAddress, entry.value));
                if (++count >= stringSamples) {
                    break;
                }
            }
            md.append("```\n");
        }

        String diff = PatchManager.getInstance().diff();
        if (!diff.startsWith("暂无")) {
            md.append("\n## 修改记录\n\n```\n").append(diff).append("```\n");
        }

        String output = optString(args, "output");
        File dest;
        if (output != null && !output.isEmpty()) {
            dest = new File(output);
        } else {
            File dir = new File(Environment.getExternalStorageDirectory(), "SoSandbox");
            if (!dir.exists() && !dir.mkdirs()) {
                dir = context.getExternalFilesDir(null);
            }
            String name = file.getName();
            if (name.endsWith(".so")) {
                name = name.substring(0, name.length() - 3);
            }
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
                    .format(new java.util.Date());
            dest = new File(dir, name + "_report_" + stamp + ".md");
        }
        File parent = dest.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new ToolException("无法创建输出目录: " + parent);
        }
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(md.toString().getBytes("UTF-8"));
            fos.getFD().sync();
        }
        McpLog.info("MCP 导出报告 -> " + dest.getAbsolutePath());
        return "报告已生成: " + dest.getAbsolutePath() + "\n大小: " + dest.length() + " 字节\n";
    }

    private void requireWritable() throws ToolException {
        if (McpPrefs.isReadOnly(context)) {
            throw new ToolException("MCP 当前为只读模式，写入已被拒绝。可在 App 的 MCP 页面关闭只读模式。");
        }
    }

    private String requirePath() throws ToolException {
        String path = DataHolder.getInstance().getSoPath();
        if (path == null || path.isEmpty()) {
            throw new ToolException("尚未加载 SO，请先调用 so_open");
        }
        return path;
    }

    private List<NativeFunction> requireFunctions() throws ToolException {
        List<NativeFunction> functions = DataHolder.getInstance().getFunctions();
        if (functions == null) {
            throw new ToolException("尚未加载 SO，请先调用 so_open");
        }
        return functions;
    }

    private NativeFunction resolveFunction(JSONObject args) throws ToolException {
        List<NativeFunction> functions = requireFunctions();
        String name = optString(args, "function");
        boolean hasOffset = args.has("offset") && !args.isNull("offset");

        if ((name == null || name.isEmpty()) && !hasOffset) {
            throw new ToolException("需要提供 function（函数名）或 offset（地址）");
        }

        if (name != null && !name.isEmpty()) {
            for (NativeFunction f : functions) {
                if (name.equals(f.getName())) {
                    return f;
                }
            }
            for (NativeFunction f : functions) {
                if (name.equals(f.getDemangledName())) {
                    return f;
                }
            }
            List<NativeFunction> partial = new ArrayList<>();
            String lower = name.toLowerCase(Locale.US);
            for (NativeFunction f : functions) {
                String demangled = f.getDemangledName();
                if (demangled != null && demangled.toLowerCase(Locale.US).contains(lower)) {
                    partial.add(f);
                }
            }
            if (partial.size() == 1) {
                return partial.get(0);
            }
            if (partial.size() > 1) {
                StringBuilder sb = new StringBuilder("函数名不唯一，请改用 offset。候选:\n");
                for (int i = 0; i < Math.min(partial.size(), 10); i++) {
                    NativeFunction f = partial.get(i);
                    sb.append("  0x").append(String.format(Locale.US, "%X", f.getOffset()))
                            .append("  ").append(f.getName()).append('\n');
                }
                throw new ToolException(sb.toString());
            }
            if (!hasOffset) {
                throw new ToolException("未找到函数: " + name);
            }
        }

        long offset = requireOffset(args, "offset");
        for (NativeFunction f : functions) {
            if (toVirtualLong(f.getOffset()) == offset) {
                return f;
            }
        }
        return new NativeFunction("sub_" + String.format(Locale.US, "%X", offset), offset, 0, "manual");
    }

    private long resolveFunctionSize(NativeFunction function, int requested) {
        long size = requested > 0 ? requested : function.getSize();
        if (size <= 0) {
            size = 256;
        }
        return Math.max(4, Math.min(size, 65536));
    }

    /**
     * 把函数的地址统一成虚拟地址（相对镜像基址）。
     * 动态加载时函数表里可能存的是绝对地址。
     */
    private long toVirtualLong(long offset) {
        long base = DataHolder.getInstance().getBaseAddress();
        if (base > 0 && offset >= base) {
            return offset - base;
        }
        return offset;
    }

    /**
     * 反汇编注释表，[字符串表, PLT 表, 函数表]。
     */
    private String[] tables() throws ToolException {
        String path = requirePath();
        if (path.equals(tableCachePath)) {
            return new String[]{cachedStringTable, cachedPltTable, cachedFuncTable};
        }
        DataHolder holder = DataHolder.getInstance();
        List<ElfParser.StringEntry> strings = holder.getStrings();
        List<PltEntry> plt = holder.getPltEntries();
        List<NativeFunction> functions = holder.getFunctions();

        StringBuilder stringTable = new StringBuilder();
        int count = 0;
        if (strings != null) {
            for (ElfParser.StringEntry e : strings) {
                if (e == null || e.value == null || e.value.length() > 200) {
                    continue;
                }
                if (stringTable.length() > 0) {
                    stringTable.append('|');
                }
                stringTable.append(String.format(Locale.US, "%X", e.virtualAddress))
                        .append('|').append(e.value);
                if (++count >= MAX_TABLE_STRINGS) {
                    break;
                }
            }
        }

        StringBuilder pltTable = new StringBuilder();
        if (plt != null) {
            for (PltEntry e : plt) {
                if (e == null || e.symbolName == null) {
                    continue;
                }
                if (pltTable.length() > 0) {
                    pltTable.append('|');
                }
                pltTable.append(String.format(Locale.US, "%X", e.offset))
                        .append('|').append(e.symbolName);
            }
        }

        StringBuilder funcTable = new StringBuilder();
        if (functions != null) {
            for (NativeFunction f : functions) {
                if (funcTable.length() > 0) {
                    funcTable.append('|');
                }
                funcTable.append(String.format(Locale.US, "%X", toVirtualLong(f.getOffset())))
                        .append('|').append(f.getDemangledName());
            }
        }

        cachedStringTable = stringTable.toString();
        cachedPltTable = pltTable.toString();
        cachedFuncTable = funcTable.toString();
        tableCachePath = path;
        return new String[]{cachedStringTable, cachedPltTable, cachedFuncTable};
    }

    private byte[] readBytes(long fileOffset, int size) throws IOException, ToolException {
        try (RandomAccessFile raf = new RandomAccessFile(requirePath(), "r")) {
            long length = raf.length();
            if (fileOffset < 0 || fileOffset >= length) {
                throw new ToolException("地址越界: 文件偏移 0x"
                        + String.format(Locale.US, "%X", fileOffset) + " 超出文件大小");
            }
            int readSize = (int) Math.min(size, length - fileOffset);
            byte[] bytes = new byte[readSize];
            raf.seek(fileOffset);
            raf.readFully(bytes);
            return bytes;
        }
    }

    private void checkElfArch(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] header = new byte[20];
            if (fis.read(header) < 20) {
                throw new ToolException("读取 ELF 头失败");
            }
            if (header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F') {
                throw new ToolException("不是有效的 ELF 文件: " + file.getAbsolutePath());
            }
            int eMachine = (header[19] & 0xFF) << 8 | (header[18] & 0xFF);
            if (eMachine == 0x28) {
                throw new ToolException("不支持 32 位 ARM SO，仅支持 ARM64");
            }
            if (eMachine != 0xB7) {
                throw new ToolException("仅支持 ARM64(aarch64)，当前 e_machine=0x"
                        + Integer.toHexString(eMachine));
            }
        }
    }

    private String hexDump(long virtualAddress, byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("地址: 0x").append(String.format(Locale.US, "%X", virtualAddress))
                .append("  长度: ").append(bytes.length).append(" 字节\n\n");
        for (int i = 0; i < bytes.length; i += 16) {
            sb.append(String.format(Locale.US, "%08X  ", virtualAddress + i));
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < bytes.length) {
                    int value = bytes[i + j] & 0xFF;
                    sb.append(String.format(Locale.US, "%02X ", value));
                    ascii.append(value >= 0x20 && value < 0x7F ? (char) value : '.');
                } else {
                    sb.append("   ");
                }
                if (j == 7) {
                    sb.append(' ');
                }
            }
            sb.append(" |").append(ascii).append("|\n");
        }
        return sb.toString();
    }

    private static boolean isNoisy(ElfParser.StringEntry entry) {
        String value = entry.value;
        String section = entry.section == null ? "" : entry.section;
        if (value.startsWith("_Z")) {
            return true;
        }
        if (".dynstr".equals(section) || ".strtab".equals(section)) {
            return true;
        }
        if (value.length() < 5) {
            return true;
        }
        int printable = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x20 && c < 0x7F) {
                printable++;
            }
        }
        return printable != value.length();
    }

    private static byte[] parseHex(String hex) {
        StringBuilder cleaned = new StringBuilder();
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (Character.digit(c, 16) >= 0) {
                cleaned.append(c);
            }
        }
        if (cleaned.length() % 2 != 0) {
            cleaned.append('0');
        }
        byte[] out = new byte[cleaned.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(String.format(Locale.US, "%02X", b & 0xFF));
        }
        return sb.toString();
    }

    private static String nameOf(Map<Long, String> names, long offset) {
        String name = names.get(offset);
        if (name == null) {
            return "sub_" + String.format(Locale.US, "%X", offset);
        }
        return name;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private static String limit(String text) {
        if (text.length() <= MAX_TEXT_OUTPUT) {
            return text;
        }
        return text.substring(0, MAX_TEXT_OUTPUT)
                + "\n... 输出过长已截断（共 " + text.length() + " 字符），请缩小范围后重试\n";
    }

    private static String optString(JSONObject args, String key) {
        if (args == null || !args.has(key) || args.isNull(key)) {
            return null;
        }
        Object value = args.opt(key);
        return value == null ? null : String.valueOf(value);
    }

    /**
     * 解析 offset：支持数字、十进制字符串、0x 前缀十六进制字符串。
     */
    private static long requireOffset(JSONObject args, String key) throws ToolException {
        if (args == null || !args.has(key) || args.isNull(key)) {
            throw new ToolException("缺少参数 " + key);
        }
        Object raw = args.opt(key);
        try {
            if (raw instanceof Number) {
                return ((Number) raw).longValue();
            }
            String text = String.valueOf(raw).trim();
            if (text.startsWith("0x") || text.startsWith("0X")) {
                return Long.parseLong(text.substring(2), 16);
            }
            if (text.matches("[0-9a-fA-F]{6,16}")) {
                return Long.parseLong(text, 16);
            }
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw new ToolException("非法的 " + key + ": " + raw);
        }
    }

    // ==================== 结果封装 ====================

    private static JSONObject text(String value) {
        try {
            JSONObject result = new JSONObject();
            JSONArray content = new JSONArray();
            content.put(new JSONObject().put("type", "text").put("text", value));
            result.put("content", content);
            result.put("isError", false);
            return result;
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    private static JSONObject error(String message) {
        try {
            JSONObject result = new JSONObject();
            JSONArray content = new JSONArray();
            content.put(new JSONObject().put("type", "text").put("text", message));
            result.put("content", content);
            result.put("isError", true);
            return result;
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    // ==================== Schema 辅助 ====================

    private static JSONObject tool(String name, String title, String description, JSONObject schema)
            throws JSONException {
        return new JSONObject()
                .put("name", name)
                .put("title", title)
                .put("description", description)
                .put("inputSchema", schema);
    }

    private static JSONObject schema() {
        return schema(new Object[0]);
    }

    private static JSONObject schema(Object... propertyPairs) {
        JSONObject properties = new JSONObject();
        JSONArray required = new JSONArray();
        try {
            for (int i = 0; i + 1 < propertyPairs.length; i += 2) {
                properties.put(String.valueOf(propertyPairs[i]), propertyPairs[i + 1]);
            }
            return new JSONObject()
                    .put("type", "object")
                    .put("properties", properties)
                    .put("required", required);
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    private static JSONObject prop(String type, String description) {
        try {
            return new JSONObject().put("type", type).put("description", description);
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    private static JSONObject offsetProp(String description) {
        try {
            JSONObject schema = new JSONObject()
                    .put("type", new JSONArray().put("integer").put("string"))
                    .put("description", description);
            return schema;
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    private static JSONObject enumProp(String[] values, String description) {
        try {
            JSONArray array = new JSONArray();
            for (String value : values) {
                array.put(value);
            }
            return new JSONObject().put("type", "string").put("enum", array).put("description", description);
        } catch (JSONException e) {
            return new JSONObject();
        }
    }

    /**
     * 工具级异常，用于把可读错误直接回给客户端。
     */
    static class ToolException extends Exception {
        ToolException(String message) {
            super(message);
        }
    }
}

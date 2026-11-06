package com.example.anative.core;

import java.util.List;
import java.util.Locale;

/**
 * 反汇编辅助表（函数名 / 字符串 / PLT）的构建。
 *
 * <p>原生引擎靠这三张表在指令后面追加 {@code ; "hello"}、{@code ; memcpy@PLT}
 * 这类注释，表本身是 {@code 地址|名字} 用 {@code |} 连接的扁平字符串，
 * 这里统一生成，避免 UI 和 MCP 各写一份。
 */
public final class DisasmTables {

    private DisasmTables() {
    }

    public static String funcTable(List<NativeFunction> funcs) {
        if (funcs == null || funcs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (NativeFunction f : funcs) {
            if (f == null) continue;
            if (sb.length() > 0) sb.append('|');
            sb.append(String.format(Locale.US, "%X", f.getOffset()))
                    .append('|').append(f.getDemangledName());
        }
        return sb.toString();
    }

    public static String stringTable(List<ElfParser.StringEntry> strings) {
        if (strings == null || strings.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (ElfParser.StringEntry e : strings) {
            if (e == null || e.value == null) continue;
            if (sb.length() > 0) sb.append('|');
            sb.append(String.format(Locale.US, "%X", e.virtualAddress))
                    .append('|').append(e.value.replace('|', ' ').replace('\n', ' '));
        }
        return sb.toString();
    }

    public static String pltTable(List<PltEntry> entries) {
        if (entries == null || entries.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (PltEntry e : entries) {
            if (e == null || e.symbolName == null) continue;
            if (sb.length() > 0) sb.append('|');
            sb.append(String.format(Locale.US, "%X", e.offset))
                    .append('|').append(e.symbolName);
        }
        return sb.toString();
    }
}

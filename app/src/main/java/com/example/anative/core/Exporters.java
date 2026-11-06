package com.example.anative.core;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 分析结果导出：把函数表变成 PC 端工具能直接消费的脚本。
 *
 * <p>Markdown 报告适合人看，但从"在手机上看完"到"回到 IDA 里继续"之间
 * 还隔着一整轮手工重命名。这里直接把符号、注释、原型写成脚本。
 */
public final class Exporters {

    private Exporters() {
    }

    /**
     * IDAPython 脚本（IDA 7.x / 8.x 通用）。
     *
     * @param moduleName 目标模块名，写进注释方便确认导入了哪个库
     */
    public static String idaPython(String moduleName, List<NativeFunction> functions, int limit) {
        StringBuilder sb = new StringBuilder();
        sb.append("# -*- coding: utf-8 -*-\n");
        sb.append("# 由 So Sandbox 生成 —— 模块: ").append(safeComment(moduleName)).append('\n');
        sb.append("# 用法: File -> Script file... 选择本文件\n");
        sb.append("import idc\n");
        sb.append("import idaapi\n\n");
        sb.append("def apply_names():\n");
        sb.append("    total = 0\n");
        sb.append("    changed = 0\n");

        int count = 0;
        for (NativeFunction fn : functions) {
            if (count >= limit) break;
            long va = fn.getOffset();
            if (va <= 0) continue;

            String name = sanitize(fn.getDemangledName() != null ? fn.getDemangledName() : fn.getName());
            String comment = buildComment(fn);

            sb.append("    total += 1\n");
            sb.append("    ea = 0x").append(Long.toHexString(va).toUpperCase(Locale.US)).append('\n');
            sb.append("    if idc.set_name(ea, ").append(pyStr(name))
                    .append(", idc.SN_NOWARN | idc.SN_FORCE):\n");
            sb.append("        changed += 1\n");
            if (comment != null) {
                sb.append("    idc.set_cmt(ea, ").append(pyStr(comment)).append(", 0)\n");
            }
            count++;
        }

        sb.append("    print('[SoSandbox] %d / %d symbols applied' % (changed, total))\n\n");
        sb.append("if __name__ == '__main__':\n");
        sb.append("    apply_names()\n");
        return sb.toString();
    }

    /**
     * Ghidra Jython 脚本。
     */
    public static String ghidraScript(String moduleName, List<NativeFunction> functions, int limit) {
        StringBuilder sb = new StringBuilder();
        sb.append("# -*- coding: utf-8 -*-\n");
        sb.append("# 由 So Sandbox 生成 —— 模块: ").append(safeComment(moduleName)).append('\n');
        sb.append("# 用法: Window -> Script Manager -> 新建 Script -> Python(Jython) 粘贴运行\n");
        sb.append("#@category SoSandbox\n\n");
        sb.append("from ghidra.program.model.symbol import SourceType\n\n");
        sb.append("def run():\n");
        sb.append("    program = currentProgram\n");
        sb.append("    listing = program.getListing()\n");
        sb.append("    fm = program.getFunctionManager()\n");
        sb.append("    space = program.getAddressFactory().getDefaultAddressSpace()\n");
        sb.append("    total = 0\n");
        sb.append("    changed = 0\n");

        int count = 0;
        for (NativeFunction fn : functions) {
            if (count >= limit) break;
            long va = fn.getOffset();
            if (va <= 0) continue;

            String name = sanitize(fn.getDemangledName() != null ? fn.getDemangledName() : fn.getName());
            String comment = buildComment(fn);

            sb.append("    total += 1\n");
            sb.append("    addr = space.getAddress(0x")
                    .append(Long.toHexString(va).toUpperCase(Locale.US)).append(")\n");
            sb.append("    try:\n");
            sb.append("        func = fm.getFunctionAt(addr)\n");
            sb.append("        if func is None:\n");
            sb.append("            func = fm.createFunction(addr, ").append(pyStr(name)).append(")\n");
            sb.append("        if func is not None:\n");
            sb.append("            func.setName(").append(pyStr(name))
                    .append(", SourceType.USER_DEFINED)\n");
            sb.append("            changed += 1\n");
            if (comment != null) {
                sb.append("        listing.setComment(addr, 0, ").append(pyStr(comment)).append(")\n");
            }
            sb.append("    except:\n");
            sb.append("        pass\n");
            count++;
        }

        sb.append("    print('[SoSandbox] %d / %d symbols applied' % (changed, total))\n\n");
        sb.append("run()\n");
        return sb.toString();
    }

    /**
     * C 头文件：函数原型按地址排序，可直接塞进辅助工程做符号声明。
     */
    public static String cHeader(String moduleName, List<NativeFunction> functions,
                                 List<String> exportedNames, List<String> importedNames) {
        String guard = "SO_SANDBOX_" + sanitize(moduleName).toUpperCase(Locale.US) + "_H";
        StringBuilder sb = new StringBuilder();
        sb.append("/*\n");
        sb.append(" * 由 So Sandbox 生成\n");
        sb.append(" * 模块: ").append(safeComment(moduleName)).append('\n');
        sb.append(" * 函数: ").append(functions.size()).append(" 个");
        if (exportedNames != null) sb.append("，导出 ").append(exportedNames.size()).append(" 个");
        if (importedNames != null) sb.append("，导入 ").append(importedNames.size()).append(" 个");
        sb.append("\n */\n\n");
        sb.append("#ifndef ").append(guard).append('\n');
        sb.append("#define ").append(guard).append("\n\n");
        sb.append("#include <stdint.h>\n\n");
        sb.append("#ifdef __cplusplus\n");
        sb.append("extern \"C\" {\n");
        sb.append("#endif\n\n");

        sb.append("/* ---------------- 函数原型 ---------------- */\n");
        for (NativeFunction fn : functions) {
            long va = fn.getOffset();
            if (va <= 0) continue;
            sb.append("/* 0x").append(Long.toHexString(va).toUpperCase(Locale.US))
                    .append("  size=").append(fn.getSize()).append(" */\n");
            sb.append(prototype(fn)).append(";\n");
        }
        sb.append('\n');

        if (exportedNames != null && !exportedNames.isEmpty()) {
            sb.append("/* ---------------- 导出符号 ---------------- */\n");
            for (String name : exportedNames) {
                sb.append("/* export */ ").append(name).append('\n');
            }
            sb.append('\n');
        }
        if (importedNames != null && !importedNames.isEmpty()) {
            sb.append("/* ---------------- 导入符号 ---------------- */\n");
            for (String name : importedNames) {
                sb.append("/* import */ ").append(name).append('\n');
            }
            sb.append('\n');
        }

        sb.append("#ifdef __cplusplus\n");
        sb.append("}\n");
        sb.append("#endif\n\n");
        sb.append("#endif /* ").append(guard).append(" */\n");
        return sb.toString();
    }

    /** 给 MCP 用的统一入口，按格式名分发 */
    public static String export(String format, String moduleName, List<NativeFunction> functions) {
        String fmt = format == null ? "ida" : format.toLowerCase(Locale.US);
        switch (fmt) {
            case "ghidra":
                return ghidraScript(moduleName, functions, 5000);
            case "cheader":
            case "c":
                return cHeader(moduleName, functions, null, null);
            case "ida":
            default:
                return idaPython(moduleName, functions, 5000);
        }
    }

    // ------------------------------------------------------------------

    private static String prototype(NativeFunction fn) {
        StringBuilder sb = new StringBuilder();
        sb.append(typeName(fn.getReturnType())).append(' ');
        sb.append(sanitize(fn.getDemangledName() != null ? fn.getDemangledName() : fn.getName()));
        sb.append('(');
        List<NativeFunction.ParamInfo> params = fn.getParams();
        if (params == null || params.isEmpty()) {
            sb.append("void");
        } else {
            for (int i = 0; i < params.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(typeName(params.get(i).type)).append(' ').append(paramName(params.get(i), i));
            }
        }
        sb.append(')');
        return sb.toString();
    }

    private static String typeName(String declared) {
        if (declared == null) return "void *";
        switch (declared) {
            case "void":
                return "void";
            case "int":
                return "int32_t";
            case "long":
                return "int64_t";
            case "float":
                return "float";
            case "double":
                return "double";
            case "string":
                return "const char *";
            default:
                return declared;
        }
    }

    private static String paramName(NativeFunction.ParamInfo p, int index) {
        if (p.name != null && !p.name.isEmpty()) return sanitize(p.name);
        return "a" + index;
    }

    private static String buildComment(NativeFunction fn) {
        StringBuilder sb = new StringBuilder();
        sb.append("SoSandbox size=").append(fn.getSize());
        if (fn.getSource() != null) sb.append(" src=").append(fn.getSource());
        if (fn.isJni()) sb.append(" JNI");
        String sig = fn.getSignatureString();
        if (sig != null && !sig.isEmpty()) {
            sb.append(" | ").append(sig.replace('\n', ' '));
        }
        return sb.toString();
    }

    /**
     * IDA / Ghidra / C 都要求合法标识符：去掉命名空间分隔符和模板尖括号，
     * 首字符不能是数字。
     */
    static String sanitize(String name) {
        if (name == null || name.isEmpty()) return "sub_unknown";
        StringBuilder sb = new StringBuilder(name.length() + 4);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_';
            if (ok) {
                sb.append(c);
            } else if (c == ':' || c == '<' || c == '>' || c == ',' || c == ' '
                    || c == '~' || c == '*' || c == '&') {
                // 命名空间分隔连写，其余折叠成单下划线
                if (c == ':' && i + 1 < name.length() && name.charAt(i + 1) == ':') {
                    if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '_') sb.append('_');
                    i++;
                } else if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '_') {
                    sb.append('_');
                }
            }
        }
        String s = sb.toString();
        if (s.isEmpty()) return "sub_unknown";
        if (s.charAt(0) >= '0' && s.charAt(0) <= '9') s = "f_" + s;
        return s;
    }

    private static String pyStr(String s) {
        StringBuilder sb = new StringBuilder("'");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') sb.append("\\\\");
            else if (c == '\'') sb.append("\\'");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '\t') sb.append("\\t");
            else sb.append(c);
        }
        return sb.append('\'').toString();
    }

    private static String safeComment(String s) {
        if (s == null) return "";
        return s.replace('\n', ' ').replace('\r', ' ');
    }

    /** 便捷：把 Map&lt;地址, 名字&gt; 转成函数列表 */
    public static java.util.List<NativeFunction> fromSymbolMap(Map<Long, String> map) {
        java.util.List<NativeFunction> out = new java.util.ArrayList<>();
        if (map == null) return out;
        for (Map.Entry<Long, String> e : map.entrySet()) {
            out.add(new NativeFunction(e.getValue(), e.getKey(), 0, "custom"));
        }
        out.sort((a, b) -> Long.compare(a.getOffset(), b.getOffset()));
        return out;
    }
}

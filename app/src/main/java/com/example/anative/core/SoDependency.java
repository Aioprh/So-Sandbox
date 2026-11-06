package com.example.anative.core;

import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SO 依赖关系解析。
 *
 * <p>一个 App 的 native 层往往是十几二十个 SO 互相依赖，靠 PLT 表一个个
 * 看太零碎。这里直接读 .dynamic 段的 DT_NEEDED / SONAME / RUNPATH，
 * 再配合 .dynsym 分出"我导出了什么"和"我向别人要了什么"，拼出完整画像。
 */
public final class SoDependency {
    private static final String TAG = "SoDependency";

    private static final int DT_NULL = 0;
    private static final int DT_NEEDED = 1;
    private static final int DT_SONAME = 14;
    private static final int DT_RPATH = 15;
    private static final int DT_RUNPATH = 29;

    public static final class Info {
        public String path;
        public String soname;
        public final List<String> needed = new ArrayList<>();
        public final List<String> runPaths = new ArrayList<>();
        public final List<String> exportedFunctions = new ArrayList<>();
        public final List<String> exportedObjects = new ArrayList<>();
        public final List<String> importedFunctions = new ArrayList<>();
        public int totalSymbols;
    }

    private SoDependency() {
    }

    public static Info parse(String soPath) throws IOException {
        File f = new File(soPath);
        if (!f.isFile()) throw new IOException("文件不存在: " + soPath);

        Info info = new Info();
        info.path = soPath;

        List<ElfParser.SectionInfo> sections = ElfParser.parseSections(soPath);
        long dynstrOffset = -1;
        ElfParser.SectionInfo dynamicSection = null;
        for (ElfParser.SectionInfo sec : sections) {
            if (".dynstr".equals(sec.name)) dynstrOffset = sec.offset;
            else if (".dynamic".equals(sec.name)) dynamicSection = sec;
        }

        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            if (dynamicSection != null && dynstrOffset >= 0) {
                readDynamic(raf, dynamicSection, dynstrOffset, info);
            }
            readSymbols(soPath, info);
        }

        Log.i(TAG, "依赖解析: needed=" + info.needed.size()
                + " export=" + info.exportedFunctions.size()
                + " import=" + info.importedFunctions.size());
        return info;
    }

    private static void readDynamic(RandomAccessFile raf, ElfParser.SectionInfo dyn,
                                    long dynstrOffset, Info info) throws IOException {
        ElfArch arch = ElfArch.detect(info.path);
        boolean is64 = arch.elf64;
        int entrySize = is64 ? 16 : 8;
        long count = dyn.size / entrySize;
        if (count <= 0 || count > 100000) return;

        byte[] buf = new byte[(int) Math.min(dyn.size, 1 << 20)];
        raf.seek(dyn.offset);
        int read = 0;
        while (read < buf.length) {
            int n = raf.read(buf, read, buf.length - read);
            if (n < 0) break;
            read += n;
        }

        for (int i = 0; i < count; i++) {
            int base = (int) (i * entrySize);
            if (base + entrySize > read) break;

            long tag;
            long val;
            if (is64) {
                tag = readLong(buf, base);
                val = readLong(buf, base + 8);
            } else {
                tag = readInt(buf, base) & 0xFFFFFFFFL;
                val = readInt(buf, base + 4) & 0xFFFFFFFFL;
            }
            if (tag == DT_NULL) break;

            String str = readString(raf, dynstrOffset + val);
            if (str == null) continue;

            switch ((int) tag) {
                case DT_NEEDED:
                    if (!info.needed.contains(str)) info.needed.add(str);
                    break;
                case DT_SONAME:
                    info.soname = str;
                    break;
                case DT_RPATH:
                case DT_RUNPATH:
                    if (!info.runPaths.contains(str)) info.runPaths.add(str);
                    break;
                default:
                    break;
            }
        }
    }

    private static void readSymbols(String soPath, Info info) throws IOException {
        List<ElfParser.SymbolInfo> symbols = ElfParser.parseSymbols(soPath);
        Set<String> exportedFn = new LinkedHashSet<>();
        Set<String> exportedObj = new LinkedHashSet<>();
        Set<String> importedFn = new LinkedHashSet<>();

        for (ElfParser.SymbolInfo sym : symbols) {
            info.totalSymbols++;
            if (sym.binding == 0) continue;  // LOCAL 不参与导出/导入

            boolean isFunc = sym.type == 2;   // STT_FUNC
            boolean isObject = sym.type == 1; // STT_OBJECT

            if (sym.isUndefined()) {
                if (isFunc || sym.type == 0) {
                    importedFn.add(sym.name);
                }
            } else {
                if (isFunc) {
                    exportedFn.add(sym.name);
                } else if (isObject && sym.size > 0) {
                    exportedObj.add(sym.name);
                }
            }
        }

        // 符号表可能同时含 symtab 与 dynsym，Set 已经去重
        importedFn.removeAll(exportedFn);

        info.exportedFunctions.addAll(exportedFn);
        info.exportedObjects.addAll(exportedObj);
        info.importedFunctions.addAll(importedFn);
    }

    private static String readString(RandomAccessFile raf, long offset) {
        try {
            if (offset < 0 || offset >= raf.length()) return null;
            raf.seek(offset);
            StringBuilder sb = new StringBuilder();
            int b;
            int guard = 0;
            while ((b = raf.read()) > 0 && guard++ < 512) {
                sb.append((char) b);
            }
            return sb.length() == 0 ? null : sb.toString();
        } catch (IOException e) {
            return null;
        }
    }

    private static int readInt(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }

    private static long readLong(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (b[off + i] & 0xFFL);
        }
        return v;
    }

    // ------------------------------------------------------------------
    // 输出
    // ------------------------------------------------------------------

    public static String format(Info info) {
        if (info == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("文件: ").append(new File(info.path).getName()).append('\n');
        if (info.soname != null) sb.append("SONAME: ").append(info.soname).append('\n');
        sb.append('\n');

        sb.append("依赖 (").append(info.needed.size()).append(")\n");
        if (info.needed.isEmpty()) {
            sb.append("  无（静态链接或不需要外部库）\n");
        } else {
            for (String n : info.needed) sb.append("  → ").append(n).append('\n');
        }
        if (!info.runPaths.isEmpty()) {
            sb.append("\n搜索路径\n");
            for (String p : info.runPaths) sb.append("  ").append(p).append('\n');
        }

        sb.append("\n导出函数 (").append(info.exportedFunctions.size()).append(")\n");
        appendList(sb, info.exportedFunctions, 60);

        sb.append("\n导出数据 (").append(info.exportedObjects.size()).append(")\n");
        appendList(sb, info.exportedObjects, 40);

        sb.append("\n导入函数 (").append(info.importedFunctions.size()).append(")\n");
        appendList(sb, info.importedFunctions, 60);

        return sb.toString();
    }

    private static void appendList(StringBuilder sb, List<String> list, int limit) {
        int n = Math.min(list.size(), limit);
        for (int i = 0; i < n; i++) {
            sb.append("  ").append(list.get(i)).append('\n');
        }
        if (list.size() > n) {
            sb.append("  ... 还有 ").append(list.size() - n).append(" 项\n");
        }
    }

    /** 生成 Graphviz DOT：当前 SO 在中间，依赖与导出各指向一侧 */
    public static String toDot(Info info) {
        if (info == null) return "digraph G {}\n";
        String self = safeId(info.soname != null ? info.soname
                : new File(info.path).getName());

        StringBuilder sb = new StringBuilder();
        sb.append("digraph so_deps {\n");
        sb.append("  rankdir=LR;\n");
        sb.append("  node [shape=box, style=rounded, fontname=\"monospace\"];\n");
        sb.append("  \"").append(self).append("\" [style=\"rounded,filled\", fillcolor=\"#2d6cdf\", fontcolor=white];\n");

        for (String dep : info.needed) {
            sb.append("  \"").append(safeId(dep)).append("\" [fillcolor=\"#eef2f7\"];\n");
            sb.append("  \"").append(self).append("\" -> \"").append(safeId(dep))
                    .append("\" [label=\"NEEDED\"];\n");
        }

        // 导出符号单独聚成一簇，超过 40 个就只画前 40 个
        int exportLimit = Math.min(info.exportedFunctions.size(), 40);
        if (exportLimit > 0) {
            sb.append("  subgraph cluster_exports {\n");
            sb.append("    label=\"导出 (").append(info.exportedFunctions.size()).append(")\";\n");
            sb.append("    style=dashed; color=\"#9aa7b8\";\n");
            for (int i = 0; i < exportLimit; i++) {
                String id = "exp_" + i;
                sb.append("    \"").append(id).append("\" [label=\"")
                        .append(shortLabel(info.exportedFunctions.get(i))).append("\", fillcolor=\"#e8f5e9\"];\n");
                sb.append("    \"").append(self).append("\" -> \"").append(id)
                        .append("\" [style=dotted, arrowhead=none];\n");
            }
            sb.append("  }\n");
        }

        sb.append("}\n");
        return sb.toString();
    }

    private static String shortLabel(String s) {
        if (s == null) return "";
        String v = s.length() > 28 ? s.substring(0, 28) + "…" : s;
        return v.replace("\"", "'");
    }

    private static String safeId(String s) {
        if (s == null) return "unknown";
        return s.replace("\"", "'");
    }
}

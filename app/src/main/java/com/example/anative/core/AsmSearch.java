package com.example.anative.core;

import android.util.Log;

import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 汇编模式搜索。
 *
 * <p>字节搜索只能找"这段机器码出现过"，回答不了"哪些函数调了 memcpy"、
 * "谁在写 0x40000000 这个标志位"。这里把函数逐个反汇编后按行匹配，
 * 支持四种查询：
 * <pre>
 *   memcpy            子串（含注释），不区分大小写
 *   m:bl              助记符精确匹配
 *   /ldr\s+x0, \[x1/  整行正则
 *   m/cb[zn]\/        助记符正则
 * </pre>
 */
public final class AsmSearch {
    private static final String TAG = "AsmSearch";

    /** 单条命中 */
    public static final class Hit {
        public final NativeFunction function;
        public final long instrVa;
        public final String text;       // 原始指令行

        Hit(NativeFunction function, long instrVa, String text) {
            this.function = function;
            this.instrVa = instrVa;
            this.text = text;
        }
    }

    public interface Progress {
        void onProgress(int done, int total, String currentFunction);
    }

    /** 每个函数最多记录多少条命中，避免一个大函数刷屏 */
    private static final int MAX_HITS_PER_FUNCTION = 6;
    private static final Pattern ADDR_LINE = Pattern.compile("^([0-9a-fA-F]{4,16}):\\s*(.*)$");

    private AsmSearch() {
    }

    public static List<Hit> search(String soPath, List<NativeFunction> functions,
                                   String query, String funcTable, String pltTable,
                                   String stringTable,
                                   int maxHits, int maxFunctions,
                                   Progress progress, AtomicBoolean cancel) {
        List<Hit> hits = new ArrayList<>();
        if (soPath == null || functions == null || functions.isEmpty()) return hits;

        Query q = Query.parse(query);
        if (q == null) return hits;

        List<NativeFunction> ordered = new ArrayList<>(functions);
        ordered.sort(Comparator.comparingLong(NativeFunction::getOffset));
        int total = Math.min(ordered.size(), maxFunctions > 0 ? maxFunctions : ordered.size());

        String fTable = funcTable == null ? "" : funcTable;
        String pTable = pltTable == null ? "" : pltTable;
        String sTable = stringTable == null ? "" : stringTable;

        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            long fileLen = raf.length();
            for (int i = 0; i < total; i++) {
                if (cancel != null && cancel.get()) break;

                NativeFunction fn = ordered.get(i);
                if (progress != null && (i % 32 == 0 || i == total - 1)) {
                    progress.onProgress(i + 1, total, fn.getDemangledName());
                }

                long va = fn.getOffset();
                long size = fn.getSize();
                if (size <= 0 || size > 65536) size = Math.min(4096, 65536);
                if (size < 4) continue;

                long fileOffset = ElfParser.virtualAddrToFileOffset(soPath, va);
                if (fileOffset < 0 || fileOffset + 4 > fileLen) continue;
                if (fileOffset + size > fileLen) size = fileLen - fileOffset;
                if (size < 4) continue;

                byte[] bytes = new byte[(int) size];
                raf.seek(fileOffset);
                raf.readFully(bytes);

                String asm = DisasmBridge.disassembleStatic(
                        soPath, bytes, va, size, fn.isThumb(), sTable, pTable, fTable);
                if (asm == null || asm.isEmpty() || asm.startsWith("ERR")) continue;

                int perFunc = 0;
                for (String rawLine : asm.split("\n")) {
                    String line = rawLine.trim();
                    Matcher m = ADDR_LINE.matcher(line);
                    if (!m.matches()) continue;

                    if (!q.matches(line)) continue;

                    long instrVa;
                    try {
                        instrVa = Long.parseLong(m.group(1), 16);
                    } catch (NumberFormatException e) {
                        instrVa = va;
                    }
                    hits.add(new Hit(fn, instrVa, line));
                    if (++perFunc >= MAX_HITS_PER_FUNCTION) break;
                    if (maxHits > 0 && hits.size() >= maxHits) return hits;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "汇编搜索失败: " + e.getMessage());
        }
        return hits;
    }

    /** 查询解析结果 */
    static final class Query {
        final Pattern pattern;
        final boolean mnemonicOnly;
        final String raw;

        private Query(Pattern pattern, boolean mnemonicOnly, String raw) {
            this.pattern = pattern;
            this.mnemonicOnly = mnemonicOnly;
            this.raw = raw;
        }

        static Query parse(String raw) {
            if (raw == null) return null;
            String q = raw.trim();
            if (q.isEmpty()) return null;

            try {
                if (q.startsWith("m/") && q.endsWith("/") && q.length() > 3) {
                    // 助记符正则：m/cb[zn]\//
                    return new Query(Pattern.compile(q.substring(2, q.length() - 1),
                            Pattern.CASE_INSENSITIVE), true, raw);
                }
                if (q.startsWith("m:")) {
                    String mn = Pattern.quote(q.substring(2).trim());
                    return new Query(Pattern.compile("^" + mn + "$",
                            Pattern.CASE_INSENSITIVE), true, raw);
                }
                if (q.startsWith("/") && q.endsWith("/") && q.length() > 2) {
                    return new Query(Pattern.compile(q.substring(1, q.length() - 1),
                            Pattern.CASE_INSENSITIVE), false, raw);
                }
                return new Query(Pattern.compile(Pattern.quote(q),
                        Pattern.CASE_INSENSITIVE), false, raw);
            } catch (Exception e) {
                // 正则写错了，退化成子串，别让用户对着空白结果猜
                return new Query(Pattern.compile(Pattern.quote(q),
                        Pattern.CASE_INSENSITIVE), false, raw);
            }
        }

        boolean matches(String line) {
            if (mnemonicOnly) {
                String body = line.substring(line.indexOf(':') + 1).trim();
                String mn;
                int space = body.indexOf(' ');
                if (space > 0) {
                    mn = body.substring(0, space);
                } else {
                    int semi = body.indexOf(';');
                    mn = semi > 0 ? body.substring(0, semi).trim() : body;
                }
                return pattern.matcher(mn).find();
            }
            return pattern.matcher(line).find();
        }
    }

    /** 结果转文本，供 MCP / 导出使用 */
    public static String format(List<Hit> hits) {
        if (hits == null || hits.isEmpty()) return "未找到匹配的指令。";
        StringBuilder sb = new StringBuilder();
        sb.append("命中 ").append(hits.size()).append(" 条指令\n\n");
        long lastFunc = Long.MIN_VALUE;
        for (Hit h : hits) {
            if (h.function.getOffset() != lastFunc) {
                if (lastFunc != Long.MIN_VALUE) sb.append('\n');
                sb.append("◆ ").append(h.function.getDemangledName())
                        .append(" @0x").append(String.format(Locale.US, "%X", h.function.getOffset()))
                        .append("  (").append(h.function.getSize()).append(" bytes)\n");
                lastFunc = h.function.getOffset();
            }
            sb.append("    ").append(h.text).append('\n');
        }
        return sb.toString();
    }
}

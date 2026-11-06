package com.example.anative.core;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 两个 SO 的函数级对比。
 *
 * <p>逆向工作中最常问的问题是"这个版本改了什么"。符号表能回答"谁新增/删除了"，
 * 但改不动符号表的情况（绝大多数加固/混淆样本）需要看代码本身。这里用
 * 函数体指纹 + 滚动窗口相似度做近似匹配：
 *
 * <ol>
 *   <li>按函数名先做一次精确匹配</li>
 *   <li>未匹配上的、且大小接近的函数，用 16 字节滚动窗口的重合率配对
 *       （相似度 ≥ 60% 视为同一函数，能处理小改动与指令插入）</li>
 *   <li>仍未配对的判为新增 / 删除</li>
 * </ol>
 *
 * <p>这种方法对"编译器换了、整体重排"的版本会给出偏低的相似度，
 * 但不会把两个无关函数错配成一对——宁可漏配，不可错配。
 */
public final class SoDiff {

    /** 判定为"同一函数"的最低相似度 */
    private static final int MATCH_THRESHOLD = 60;
    /** 滚动窗口大小（字节） */
    private static final int WINDOW = 16;

    public static final String KIND_ADDED = "added";
    public static final String KIND_REMOVED = "removed";
    public static final String KIND_CHANGED = "changed";
    public static final String KIND_SAME = "same";

    /** 单个函数的对比结果 */
    public static final class FunctionChange {
        public String name;
        public long oldOffset = -1;
        public long newOffset = -1;
        public long oldSize;
        public long newSize;
        /** 0-100，仅对成对函数有意义 */
        public int similarity = 100;
        public String kind = KIND_SAME;
        public String oldSha = "";
        public String newSha = "";

        public long deltaSize() {
            return newSize - oldSize;
        }
    }

    /** 整体对比结果 */
    public static final class Result {
        public final List<FunctionChange> added = new ArrayList<>();
        public final List<FunctionChange> removed = new ArrayList<>();
        public final List<FunctionChange> changed = new ArrayList<>();
        public final List<FunctionChange> same = new ArrayList<>();

        public int oldFunctionCount;
        public int newFunctionCount;
        public String oldPath = "";
        public String newPath = "";
        public String oldArch = "";
        public String newArch = "";

        /** 整体相似度：相同函数 + 变更函数按相似度加权，分母为两边函数数较大者 */
        public int overallSimilarity() {
            if (oldFunctionCount == 0 && newFunctionCount == 0) return 100;
            double score = same.size();
            for (FunctionChange c : changed) score += c.similarity / 100.0;
            int denom = Math.max(oldFunctionCount, newFunctionCount);
            if (denom <= 0) return 100;
            return (int) Math.round(Math.min(1.0, score / denom) * 100);
        }

        public int totalChanges() {
            return added.size() + removed.size() + changed.size();
        }

        public String summaryLine() {
            return String.format(Locale.US,
                    "旧: %d 个函数   新: %d 个函数   相同: %d   变更: %d   新增: %d   删除: %d   整体相似度: %d%%",
                    oldFunctionCount, newFunctionCount, same.size(), changed.size(),
                    added.size(), removed.size(), overallSimilarity());
        }

        /** 生成 Markdown 报告，可直接写文件或喂给 MCP 客户端 */
        public String toMarkdown(int maxRows) {
            StringBuilder sb = new StringBuilder();
            sb.append("# SO 版本对比\n\n");
            sb.append("- 旧文件: `").append(oldPath).append("` (").append(oldArch).append(")\n");
            sb.append("- 新文件: `").append(newPath).append("` (").append(newArch).append(")\n");
            sb.append("- ").append(summaryLine()).append("\n\n");

            appendSection(sb, "变更的函数", changed, maxRows, true);
            appendSection(sb, "新增的函数", added, maxRows, false);
            appendSection(sb, "删除的函数", removed, maxRows, false);
            return sb.toString();
        }

        private void appendSection(StringBuilder sb, String title, List<FunctionChange> list,
                                   int maxRows, boolean withSimilarity) {
            if (list.isEmpty()) return;
            sb.append("## ").append(title).append(" (").append(list.size()).append(")\n\n");
            if (withSimilarity) {
                sb.append("| 函数 | 旧大小 | 新大小 | 变化 | 相似度 |\n");
                sb.append("|---|---:|---:|---:|---:|\n");
            } else {
                sb.append("| 函数 | 大小 | 偏移 |\n");
                sb.append("|---|---:|---|\n");
            }
            int n = Math.min(list.size(), maxRows);
            for (int i = 0; i < n; i++) {
                FunctionChange c = list.get(i);
                if (withSimilarity) {
                    sb.append(String.format(Locale.US, "| `%s` | %d | %d | %+d | %d%% |\n",
                            escape(c.name), c.oldSize, c.newSize, c.deltaSize(), c.similarity));
                } else {
                    long off = KIND_ADDED.equals(c.kind) ? c.newOffset : c.oldOffset;
                    long size = KIND_ADDED.equals(c.kind) ? c.newSize : c.oldSize;
                    sb.append(String.format(Locale.US, "| `%s` | %d | 0x%X |\n",
                            escape(c.name), size, off));
                }
            }
            if (list.size() > n) {
                sb.append("\n> 其余 ").append(list.size() - n).append(" 条已省略\n");
            }
            sb.append('\n');
        }

        private static String escape(String s) {
            if (s == null) return "";
            return s.replace("|", "\\|").replace("\n", " ");
        }
    }

    private SoDiff() {
    }

    /**
     * 对比两个 SO。
     *
     * @throws IOException 任一文件不可读
     */
    public static Result compare(String oldPath, String newPath) throws IOException {
        Result result = new Result();
        result.oldPath = oldPath;
        result.newPath = newPath;

        ElfArch oldArch = ElfArch.detect(oldPath);
        ElfArch newArch = ElfArch.detect(newPath);
        result.oldArch = oldArch.describe();
        result.newArch = newArch.describe();

        List<NativeFunction> oldFuncs = loadFunctions(oldPath);
        List<NativeFunction> newFuncs = loadFunctions(newPath);
        result.oldFunctionCount = oldFuncs.size();
        result.newFunctionCount = newFuncs.size();

        Map<String, byte[]> oldCode = readCode(oldPath, oldFuncs, oldArch);
        Map<String, byte[]> newCode = readCode(newPath, newFuncs, newArch);

        // 1) 按名字精确配对
        Map<String, NativeFunction> newByName = new LinkedHashMap<>();
        for (NativeFunction f : newFuncs) newByName.put(f.getName(), f);
        Set<String> usedNew = new HashSet<>();

        List<NativeFunction> pendingOld = new ArrayList<>();
        for (NativeFunction of : oldFuncs) {
            NativeFunction nf = newByName.get(of.getName());
            if (nf != null) {
                usedNew.add(nf.getName());
                FunctionChange c = pair(of, nf, oldCode.get(codeKey(of)), newCode.get(codeKey(nf)));
                dispatch(result, c);
            } else {
                pendingOld.add(of);
            }
        }

        List<NativeFunction> pendingNew = new ArrayList<>();
        for (NativeFunction nf : newFuncs) {
            if (!usedNew.contains(nf.getName())) pendingNew.add(nf);
        }

        // 2) 未配对的按相似度贪心配对
        pendingOld.sort(Comparator.comparingLong(NativeFunction::getSize).reversed());
        boolean[] newUsed = new boolean[pendingNew.size()];
        for (NativeFunction of : pendingOld) {
            byte[] oc = oldCode.get(codeKey(of));
            int bestIdx = -1;
            int bestSim = 0;
            for (int i = 0; i < pendingNew.size(); i++) {
                if (newUsed[i]) continue;
                NativeFunction nf = pendingNew.get(i);
                // 大小差异超过 3 倍的不可能是同一函数，跳过以省时间
                long lo = Math.max(4, Math.min(of.getSize(), nf.getSize()));
                long hi = Math.max(of.getSize(), nf.getSize());
                if (hi > lo * 3 && hi - lo > 64) continue;
                int sim = similarity(oc, newCode.get(codeKey(nf)));
                if (sim > bestSim) {
                    bestSim = sim;
                    bestIdx = i;
                }
            }
            if (bestIdx >= 0 && bestSim >= MATCH_THRESHOLD) {
                newUsed[bestIdx] = true;
                FunctionChange c = pair(of, pendingNew.get(bestIdx), oc,
                        newCode.get(codeKey(pendingNew.get(bestIdx))));
                // 名字不同，但确实是同一函数：标注为新名字
                dispatch(result, c);
            } else {
                FunctionChange c = new FunctionChange();
                c.name = of.getName();
                c.oldOffset = of.getOffset();
                c.oldSize = of.getSize();
                c.kind = KIND_REMOVED;
                result.removed.add(c);
            }
        }
        for (int i = 0; i < pendingNew.size(); i++) {
            if (newUsed[i]) continue;
            NativeFunction nf = pendingNew.get(i);
            FunctionChange c = new FunctionChange();
            c.name = nf.getName();
            c.newOffset = nf.getOffset();
            c.newSize = nf.getSize();
            c.kind = KIND_ADDED;
            result.added.add(c);
        }

        sort(result);
        return result;
    }

    private static void dispatch(Result result, FunctionChange c) {
        if (KIND_SAME.equals(c.kind)) result.same.add(c);
        else if (KIND_CHANGED.equals(c.kind)) result.changed.add(c);
        else if (KIND_ADDED.equals(c.kind)) result.added.add(c);
        else result.removed.add(c);
    }

    private static void sort(Result r) {
        // 变化最大的排前面
        r.changed.sort(Comparator.comparingInt((FunctionChange c) -> c.similarity)
                .thenComparingLong(c -> -Math.abs(c.deltaSize())));
        r.added.sort(Comparator.comparingLong((FunctionChange c) -> -c.newSize));
        r.removed.sort(Comparator.comparingLong((FunctionChange c) -> -c.oldSize));
        r.same.sort(Comparator.comparing(c -> c.name == null ? "" : c.name));
    }

    private static FunctionChange pair(NativeFunction of, NativeFunction nf,
                                       byte[] oc, byte[] nc) {
        FunctionChange c = new FunctionChange();
        c.name = nf.getName() != null ? nf.getName() : of.getName();
        c.oldOffset = of.getOffset();
        c.newOffset = nf.getOffset();
        c.oldSize = of.getSize();
        c.newSize = nf.getSize();
        c.oldSha = sha1(oc);
        c.newSha = sha1(nc);
        c.similarity = similarity(oc, nc);
        c.kind = c.similarity >= 99 ? KIND_SAME : KIND_CHANGED;
        return c;
    }

    private static String codeKey(NativeFunction f) {
        return f.getName() + "@" + Long.toHexString(f.getOffset());
    }

    private static List<NativeFunction> loadFunctions(String path) {
        try {
            List<NativeFunction> funcs = ElfParser.parseFunctions(path, "precise");
            // 符号被剥离的样本 precise 模式几乎为空，退回 balanced
            if (funcs.size() < 20) {
                funcs = ElfParser.parseFunctions(path, "balanced");
            }
            return funcs;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    /** 把每个函数的代码读进内存，键为函数名 */
    private static Map<String, byte[]> readCode(String path, List<NativeFunction> funcs,
                                                ElfArch arch) {
        Map<String, byte[]> map = new HashMap<>();
        try (RandomAccessFile raf = new RandomAccessFile(path, "r")) {
            long len = raf.length();
            for (NativeFunction f : funcs) {
                long size = f.getSize();
                if (size <= 0) size = 64;
                if (size > 65536) size = 65536;
                long off = ElfParser.virtualAddrToFileOffset(path, f.getOffset());
                if (off < 0 || off >= len) continue;
                if (off + size > len) size = len - off;
                if (size <= 0) continue;
                byte[] buf = new byte[(int) size];
                raf.seek(off);
                raf.readFully(buf);
                map.put(codeKey(f), buf);
            }
        } catch (Exception ignored) {
        }
        return map;
    }

    /**
     * 相似度：把 a 的 16 字节滑窗（步长 4）在 b 的滑窗集合里查命中率，
     * 再做对称平均。插入/删除少量指令时窗口仍能大量命中，比逐字节比较鲁棒。
     */
    static int similarity(byte[] a, byte[] b) {
        if (a == null && b == null) return 100;
        if (a == null || b == null) return 0;
        if (a.length == 0 && b.length == 0) return 100;
        if (a.length == 0 || b.length == 0) return 0;
        if (a.length == b.length && java.util.Arrays.equals(a, b)) return 100;

        Set<Long> setB = windows(b);
        int hitA = 0, totalA = 0;
        for (long h : windowList(a)) {
            totalA++;
            if (setB.contains(h)) hitA++;
        }
        Set<Long> setA = windows(a);
        int hitB = 0, totalB = 0;
        for (long h : windowList(b)) {
            totalB++;
            if (setA.contains(h)) hitB++;
        }
        double ra = totalA == 0 ? 0 : (double) hitA / totalA;
        double rb = totalB == 0 ? 0 : (double) hitB / totalB;
        // 取较小者，避免"短函数完全包含于长函数"被高估
        return (int) Math.round(Math.min(ra, rb) * 100);
    }

    private static List<Long> windowList(byte[] data) {
        List<Long> out = new ArrayList<>(Math.max(1, data.length / 4));
        if (data.length < WINDOW) {
            out.add(hash(data, 0, data.length));
            return out;
        }
        for (int i = 0; i + WINDOW <= data.length; i += 4) {
            out.add(hash(data, i, WINDOW));
        }
        return out;
    }

    private static Set<Long> windows(byte[] data) {
        return new HashSet<>(windowList(data));
    }

    private static long hash(byte[] d, int off, int len) {
        long h = 1125899906842597L;
        for (int i = 0; i < len; i++) {
            h = 31 * h + (d[off + i] & 0xFF);
        }
        return h;
    }

    static String sha1(byte[] data) {
        if (data == null) return "";
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
            byte[] dig = md.digest(data);
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) sb.append(String.format(Locale.US, "%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}

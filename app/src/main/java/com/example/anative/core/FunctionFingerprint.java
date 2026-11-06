package com.example.anative.core;

import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 函数指纹与跨库克隆检测。
 *
 * <p>用途是回答"这段代码是不是从别的库里抄过来的"：同一个静态库被链进
 * 多个 SO 时，函数体字节完全一致，即使符号被 strip 也能对上。
 *
 * <p>算法是 bottom-k minhash：对函数体做 4 字节滑窗，取 k 个最小的哈希值
 * 作为指纹。两个指纹集合的交集大小除以 k，就是 Jaccard 相似度的无偏估计，
 * 比对成本是 O(k) 而不是 O(函数长度)。
 *
 * <p>注意它比的是**机器码**，不是语义。同一份源码用不同编译器/优化级别
 * 编译出来的两份库对不上，这是方法本身的边界。
 */
public final class FunctionFingerprint {
    private static final int K = 32;
    private static final int MIN_FUNCTION_SIZE = 16;
    private static final int MAX_FUNCTION_SIZE = 8192;

    /** 一个已建好指纹的函数 */
    public static final class Entry {
        public final String soPath;
        public final String soName;
        public final NativeFunction function;
        public final int[] sketch;      // 升序排列的 bottom-k 哈希
        public final int codeSize;

        Entry(String soPath, String soName, NativeFunction function, int[] sketch, int codeSize) {
            this.soPath = soPath;
            this.soName = soName;
            this.function = function;
            this.sketch = sketch;
            this.codeSize = codeSize;
        }
    }

    /** 一对克隆 */
    public static final class Match {
        public final Entry left;
        public final Entry right;
        public final double similarity;

        Match(Entry left, Entry right, double similarity) {
            this.left = left;
            this.right = right;
            this.similarity = similarity;
        }
    }

    private FunctionFingerprint() {
    }

    /** 为单个 SO 的所有函数建指纹。读不到的条目会被跳过。 */
    public static List<Entry> build(String soPath, List<NativeFunction> functions) {
        List<Entry> out = new ArrayList<>();
        if (soPath == null || functions == null) return out;

        String soName = new java.io.File(soPath).getName();
        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            long fileLen = raf.length();
            for (NativeFunction fn : functions) {
                if (fn.getOffset() <= 0) continue;

                long size = fn.getSize();
                if (size < MIN_FUNCTION_SIZE) size = MIN_FUNCTION_SIZE;
                if (size > MAX_FUNCTION_SIZE) size = MAX_FUNCTION_SIZE;

                long fileOffset = ElfParser.virtualAddrToFileOffset(soPath, fn.getOffset());
                if (fileOffset < 0 || fileOffset + MIN_FUNCTION_SIZE > fileLen) continue;
                if (fileOffset + size > fileLen) size = fileLen - fileOffset;

                byte[] bytes = new byte[(int) size];
                raf.seek(fileOffset);
                raf.readFully(bytes);

                int[] sketch = sketch(bytes);
                if (sketch.length < K / 2) continue;
                out.add(new Entry(soPath, soName, fn, sketch, (int) size));
            }
        } catch (Exception ignored) {
            // 单个库读失败不影响其他库
        }
        return out;
    }

    /**
     * 在 {@code index} 中查找与 {@code query} 相似度 ≥ threshold 的函数。
     */
    public static List<Match> findClones(Entry query, List<Entry> index, double threshold) {
        List<Match> out = new ArrayList<>();
        if (query == null || index == null) return out;

        for (Entry candidate : index) {
            if (candidate == query) continue;
            if (candidate.soPath.equals(query.soPath)
                    && candidate.function.getOffset() == query.function.getOffset()) {
                continue; // 自己
            }
            // 快速排除：大小差 4 倍以上不可能同源
            if (query.codeSize > 0 && candidate.codeSize > 0) {
                double ratio = (double) query.codeSize / candidate.codeSize;
                if (ratio > 4 || ratio < 0.25) continue;
            }
            double sim = similarity(query.sketch, candidate.sketch);
            if (sim >= threshold) {
                out.add(new Match(query, candidate, sim));
            }
        }
        out.sort((a, b) -> Double.compare(b.similarity, a.similarity));
        return out;
    }

    /** 两个 SO 之间的全部克隆对（按相似度降序，去重） */
    public static List<Match> compare(List<Entry> left, List<Entry> right, double threshold, int limit) {
        List<Match> out = new ArrayList<>();
        if (left == null || right == null) return out;

        for (Entry a : left) {
            for (Entry b : right) {
                if (a.codeSize > 0 && b.codeSize > 0) {
                    double ratio = (double) a.codeSize / b.codeSize;
                    if (ratio > 4 || ratio < 0.25) continue;
                }
                double sim = similarity(a.sketch, b.sketch);
                if (sim >= threshold) {
                    out.add(new Match(a, b, sim));
                    if (limit > 0 && out.size() >= limit * 4) break;
                }
            }
            if (limit > 0 && out.size() >= limit * 4) break;
        }
        out.sort((x, y) -> Double.compare(y.similarity, x.similarity));
        if (limit > 0 && out.size() > limit) {
            return new ArrayList<>(out.subList(0, limit));
        }
        return out;
    }

    /**
     * bottom-k 指纹：4 字节滑窗 → FNV-1a → 保留最小的 k 个。
     * 滑窗步长为 1，保证任意单字节变化都会影响 k 个哈希中的若干项。
     */
    static int[] sketch(byte[] code) {
        if (code == null || code.length < 4) return new int[0];

        int[] buf = new int[Math.min(code.length - 3, 8192)];
        int count = 0;
        for (int i = 0; i + 4 <= code.length && count < buf.length; i++) {
            int h = 0x811C9DC5;
            for (int j = 0; j < 4; j++) {
                h ^= (code[i + j] & 0xFF);
                h *= 0x01000193;
            }
            buf[count++] = h;
        }
        if (count == 0) return new int[0];

        Arrays.sort(buf, 0, count);
        // 去重后取前 K 个
        int[] out = new int[Math.min(K, count)];
        int filled = 0;
        int prev = 0;
        boolean hasPrev = false;
        for (int i = 0; i < count && filled < out.length; i++) {
            if (hasPrev && buf[i] == prev) continue;
            out[filled++] = buf[i];
            prev = buf[i];
            hasPrev = true;
        }
        return filled == out.length ? out : Arrays.copyOf(out, filled);
    }

    /** 基于 bottom-k 的 Jaccard 估计 */
    static double similarity(int[] a, int[] b) {
        if (a == null || b == null || a.length == 0 || b.length == 0) return 0;
        int i = 0, j = 0, inter = 0;
        while (i < a.length && j < b.length) {
            if (a[i] == b[j]) {
                inter++;
                i++;
                j++;
            } else if (a[i] < b[j]) {
                i++;
            } else {
                j++;
            }
        }
        int union = a.length + b.length - inter;
        if (union <= 0) return 0;
        return (double) inter / union;
    }

    /** 结果转文本，供 MCP 使用 */
    public static String format(List<Match> matches) {
        if (matches == null || matches.isEmpty()) return "未发现同源函数。";
        StringBuilder sb = new StringBuilder();
        sb.append("发现 ").append(matches.size()).append(" 对同源函数\n\n");
        for (Match m : matches) {
            sb.append(String.format(java.util.Locale.US, "%.0f%%  ", m.similarity * 100));
            sb.append(m.left.function.getDemangledName())
                    .append(" @").append(m.left.soName)
                    .append("  ==  ")
                    .append(m.right.function.getDemangledName())
                    .append(" @").append(m.right.soName)
                    .append('\n');
        }
        return sb.toString();
    }
}

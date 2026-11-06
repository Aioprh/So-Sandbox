package com.example.anative.core;

import java.util.ArrayList;
import java.util.List;

/**
 * 指令级 diff。
 *
 * <p>函数级相似度只能告诉你"变了 40%"，看不出改了什么。这里把两份反汇编
 * 按指令序列做 LCS，输出 `-`/`+` 行。
 *
 * <p>关键点是归一化：两个版本里同一段代码的地址必然不同，如果按原文比对，
 * 每条 `bl 0x1234` 都会被判成变化。所以分支类指令的目标地址统一折叠成
 * {@code <TARGET>}；其余立即数保持原样，这样"常量从 0x10 改成 0x20"仍然可见。
 */
public final class AsmDiff {

    public static final class Line {
        public final char op;        // ' ' 未变, '-' 仅旧版, '+' 仅新版
        public final String text;    // 展示用原文（已去掉地址前缀）

        Line(char op, String text) {
            this.op = op;
            this.text = text;
        }

        public boolean changed() {
            return op != ' ';
        }
    }

    public static final class Result {
        public final List<Line> lines = new ArrayList<>();
        public int unchanged;
        public int removed;
        public int added;

        public int changeCount() {
            return removed + added;
        }

        /** 与旧版本的指令重合率，0-100 */
        public int similarity() {
            int total = unchanged + removed;
            if (total == 0) return added == 0 ? 100 : 0;
            return (int) Math.round(unchanged * 100.0 / total);
        }
    }

    private AsmDiff() {
    }

    public static List<String> splitInstructions(String asm) {
        List<String> out = new ArrayList<>();
        if (asm == null) return out;
        for (String raw : asm.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            if (line.startsWith(";")) continue;      // 头部统计注释
            if (!line.matches("^[0-9a-fA-F]+:.*")) continue; // 非指令行
            out.add(raw);
        }
        return out;
    }

    /**
     * 对两份反汇编文本做指令级比对。
     */
    public static Result diff(String oldAsm, String newAsm) {
        return diffInstructions(splitInstructions(oldAsm), splitInstructions(newAsm));
    }

    public static Result diffInstructions(List<String> oldLines, List<String> newLines) {
        Result result = new Result();
        int n = oldLines.size();
        int m = newLines.size();

        List<String> a = new ArrayList<>(n);
        for (String s : oldLines) a.add(normalize(s));
        List<String> b = new ArrayList<>(m);
        for (String s : newLines) b.add(normalize(s));

        // 指令数超过阈值时 LCS 表会吃掉上百 MB 内存，退化成顺序对齐
        boolean useLcs = (long) n * m <= 4_000_000L;

        int[][] lcs = null;
        if (useLcs && n > 0 && m > 0) {
            lcs = new int[n + 1][m + 1];
            for (int i = n - 1; i >= 0; i--) {
                for (int j = m - 1; j >= 0; j--) {
                    if (a.get(i).equals(b.get(j))) {
                        lcs[i][j] = lcs[i + 1][j + 1] + 1;
                    } else {
                        lcs[i][j] = Math.max(lcs[i + 1][j], lcs[i][j + 1]);
                    }
                }
            }
        }

        if (lcs != null) {
            int i = 0, j = 0;
            while (i < n && j < m) {
                if (a.get(i).equals(b.get(j))) {
                    result.lines.add(new Line(' ', stripAddress(oldLines.get(i))));
                    result.unchanged++;
                    i++;
                    j++;
                } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
                    result.lines.add(new Line('-', stripAddress(oldLines.get(i))));
                    result.removed++;
                    i++;
                } else {
                    result.lines.add(new Line('+', stripAddress(newLines.get(j))));
                    result.added++;
                    j++;
                }
            }
            while (i < n) {
                result.lines.add(new Line('-', stripAddress(oldLines.get(i++))));
                result.removed++;
            }
            while (j < m) {
                result.lines.add(new Line('+', stripAddress(newLines.get(j++))));
                result.added++;
            }
        } else {
            int common = Math.min(n, m);
            for (int k = 0; k < common; k++) {
                if (a.get(k).equals(b.get(k))) {
                    result.lines.add(new Line(' ', stripAddress(oldLines.get(k))));
                    result.unchanged++;
                } else {
                    result.lines.add(new Line('-', stripAddress(oldLines.get(k))));
                    result.lines.add(new Line('+', stripAddress(newLines.get(k))));
                    result.removed++;
                    result.added++;
                }
            }
            for (int k = common; k < n; k++) {
                result.lines.add(new Line('-', stripAddress(oldLines.get(k))));
                result.removed++;
            }
            for (int k = common; k < m; k++) {
                result.lines.add(new Line('+', stripAddress(newLines.get(k))));
                result.added++;
            }
        }

        return result;
    }

    /** 折叠相同行的连续段，减少长函数的输出噪音 */
    public static String renderText(Result result, int contextLines) {
        if (result == null) return "";
        StringBuilder sb = new StringBuilder();
        int i = 0;
        List<Line> lines = result.lines;
        while (i < lines.size()) {
            if (lines.get(i).changed()) {
                sb.append(lines.get(i).op).append(' ').append(lines.get(i).text).append('\n');
                i++;
                continue;
            }
            int start = i;
            while (i < lines.size() && !lines.get(i).changed()) i++;
            int runLen = i - start;
            if (runLen <= contextLines * 2 + 1) {
                for (int k = start; k < i; k++) {
                    sb.append("  ").append(lines.get(k).text).append('\n');
                }
            } else {
                for (int k = start; k < start + contextLines; k++) {
                    sb.append("  ").append(lines.get(k).text).append('\n');
                }
                sb.append("  ... ").append(runLen - contextLines * 2).append(" 条相同指令 ...\n");
                for (int k = i - contextLines; k < i; k++) {
                    sb.append("  ").append(lines.get(k).text).append('\n');
                }
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------

    private static String stripAddress(String line) {
        return line.replaceFirst("^\\s*[0-9a-fA-F]+:\\s{0,2}", "").trim();
    }

    /** 归一化：去地址、去注释、压缩空白；分支目标折叠成 &lt;TARGET&gt; */
    static String normalize(String line) {
        String s = stripAddress(line);
        int semi = s.indexOf(';');
        if (semi >= 0) s = s.substring(0, semi);
        s = s.trim().replaceAll("\\s+", " ");
        if (s.isEmpty()) return s;

        String mnemonic = s;
        int space = s.indexOf(' ');
        if (space > 0) mnemonic = s.substring(0, space);

        // 分支/跳转的目标地址两版必然不同，折叠掉；条件分支前缀 cb/tb 也要覆盖
        if (mnemonic.startsWith("b") || mnemonic.startsWith("cb")
                || mnemonic.startsWith("tb") || mnemonic.equals("blx")) {
            s = s.replaceAll("0x[0-9a-fA-F]+", "<TARGET>");
            s = s.replaceAll("(?<= )\\+?-?\\d+$", "<TARGET>");
        }
        return s;
    }
}

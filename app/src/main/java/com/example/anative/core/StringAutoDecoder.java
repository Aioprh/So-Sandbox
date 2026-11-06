package com.example.anative.core;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * 字符串自动解密。
 *
 * <p>手动解码器要人一条条粘进去试，实际排查里真正的问题是"这个库有没有藏
 * 东西"。这里批量扫一遍字符串表，对每条可疑串尝试 Base64 / Hex / URL /
 * 单字节 XOR / 反转，用「像不像有意义的文本」打分决定是否值得报出来。
 *
 * <p>打分刻意保守：只报明显变好的结果。宁可漏报，也不要让几十条误报把
 * 真正的线索埋掉。
 */
public final class StringAutoDecoder {

    public static final class Finding {
        public final String original;
        public final String method;
        public final String key;
        public final String result;
        public final int confidence;
        public final long virtualAddress;

        Finding(String original, String method, String key, String result,
                int confidence, long virtualAddress) {
            this.original = original;
            this.method = method;
            this.key = key;
            this.result = result;
            this.confidence = confidence;
            this.virtualAddress = virtualAddress;
        }
    }

    /** 排查时优先关注的词，命中直接加分 */
    private static final String[] SIGNAL_WORDS = {
            "http://", "https://", ".so", ".dex", ".apk", "java", "android",
            "class", "method", "error", "exception", "token", "secret", "password",
            "key=", "api", "user", "login", "sign", "encrypt", "decrypt", "assets/",
            "/data/", "/sdcard/", "config", "debug", "root", "su", "package",
    };

    private StringAutoDecoder() {
    }

    /**
     * 批量扫描。
     *
     * @param maxScan     最多处理多少条输入（按长度优先，短串信息量低先跳过）
     * @param maxFindings 最多返回多少条结果
     */
    public static List<Finding> scan(List<ElfParser.StringEntry> strings,
                                     int maxScan, int maxFindings) {
        List<Finding> out = new ArrayList<>();
        if (strings == null || strings.isEmpty()) return out;

        int scanned = 0;
        for (ElfParser.StringEntry entry : strings) {
            if (scanned >= maxScan) break;
            String s = entry.value;
            if (s == null) continue;
            if (s.length() < 8 || s.length() > 512) continue;
            if (!isMostlyPrintable(s)) continue;

            scanned++;
            Finding best = analyze(s, entry.virtualAddress);
            if (best != null) {
                out.add(best);
                if (out.size() >= maxFindings) break;
            }
        }

        Collections.sort(out, (a, b) -> b.confidence - a.confidence);
        return out;
    }

    /** 对单条字符串做全部尝试，返回最可信的一条 */
    static Finding analyze(String s, long va) {
        int baseScore = textScore(s);
        // 原串本身就很像正常文本，多半不是密文，别浪费算力
        boolean suspicious = baseScore < 55 || looksEncoded(s);
        if (!suspicious) return null;

        Finding best = null;

        String b64 = tryBase64(s);
        if (b64 != null) {
            int sc = textScore(b64) + 10;
            if (sc > baseScore + 15) best = better(best, new Finding(s, "Base64", "-", b64, clamp(sc), va));
        }

        String hex = tryHex(s);
        if (hex != null) {
            int sc = textScore(hex) + 8;
            if (sc > baseScore + 15) best = better(best, new Finding(s, "Hex", "-", hex, clamp(sc), va));
        }

        String url = tryUrl(s);
        if (url != null && !url.equals(s)) {
            int sc = textScore(url) + 5;
            if (sc > baseScore + 10) best = better(best, new Finding(s, "URL", "-", url, clamp(sc), va));
        }

        String reversed = new StringBuilder(s).reverse().toString();
        if (!reversed.equals(s)) {
            int sc = textScore(reversed);
            if (sc > baseScore + 20) best = better(best, new Finding(s, "Reverse", "-", reversed, clamp(sc), va));
        }

        Finding xor = trySingleByteXor(s, baseScore, va);
        if (xor != null) best = better(best, xor);

        return best;
    }

    /** 单字节 XOR：256 个 key 里挑评分最高的，要求明显优于原串 */
    static Finding trySingleByteXor(String s, int baseScore, long va) {
        byte[] raw = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (raw.length == 0 || raw.length > 256) return null;

        int bestKey = -1;
        int bestScore = baseScore + 18;   // 门槛：至少比原串高 18 分
        String bestText = null;

        for (int key = 1; key < 256; key++) {
            // 先用前 32 字节快速筛，命中率低的 key 直接丢
            int probe = Math.min(raw.length, 32);
            String head = xorToString(raw, key, probe);
            if (textScore(head) < 55) continue;

            String full = xorToString(raw, key, raw.length);
            int sc = textScore(full);
            if (sc > bestScore) {
                bestScore = sc;
                bestKey = key;
                bestText = full;
            }
        }

        if (bestKey < 0 || bestText == null) return null;
        return new Finding(s, "XOR", String.format(Locale.US, "0x%02X", bestKey),
                bestText, clamp(bestScore), va);
    }

    private static String xorToString(byte[] raw, int key, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (raw[i] ^ key);
        }
        return new String(out, java.nio.charset.StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // 各类尝试
    // ------------------------------------------------------------------

    private static String tryBase64(String s) {
        if (!s.matches("^[A-Za-z0-9+/]{8,}={0,2}$")) return null;
        if (s.length() % 4 != 0 && !s.endsWith("=")) return null;
        try {
            byte[] decoded = android.util.Base64.decode(s, android.util.Base64.DEFAULT);
            if (decoded == null || decoded.length < 4) return null;
            String text = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
            return isMostlyPrintable(text) ? text : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String tryHex(String s) {
        String body = s;
        if (body.startsWith("0x") || body.startsWith("0X")) body = body.substring(2);
        if (!body.matches("^[0-9a-fA-F]+$") || body.length() % 2 != 0 || body.length() < 8) return null;
        try {
            byte[] out = new byte[body.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(body.substring(i * 2, i * 2 + 2), 16);
            }
            String text = new String(out, java.nio.charset.StandardCharsets.UTF_8);
            return isMostlyPrintable(text) ? text : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String tryUrl(String s) {
        if (!s.contains("%") && !s.contains("+")) return null;
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // 评分
    // ------------------------------------------------------------------

    /**
     * 「像不像有意义的文本」，0-100。
     *
     * <p>不是通用语言模型打分，只看三件事：可打印率、词形结构、是否命中
     * 逆向排查里的高频关键词。密文和乱码在这三项上都会明显偏低。
     */
    public static int textScore(String s) {
        if (s == null || s.length() < 3) return 0;

        int len = s.length();
        int printable = 0;
        int letters = 0;
        int spaces = 0;
        int digits = 0;
        int cjk = 0;

        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7F) printable++;
            if (Character.isLetter(c)) letters++;
            if (c == ' ') spaces++;
            if (Character.isDigit(c)) digits++;
            if (c >= 0x4E00 && c <= 0x9FFF) cjk++;
        }

        double printableRatio = (double) printable / len;
        if (printableRatio < 0.75 && cjk == 0) return (int) (printableRatio * 30);

        int score = (int) (printableRatio * 35);
        score += Math.min(15, len / 6);
        if (spaces > 0) score += Math.min(10, spaces);
        if (cjk > 0) score += Math.min(10, cjk);

        String lower = s.toLowerCase(Locale.US);
        for (String word : SIGNAL_WORDS) {
            if (lower.contains(word)) {
                score += 18;
                break;
            }
        }

        // 乱码特征：大量符号堆积、没有字母
        if (letters == 0 && digits == 0 && cjk == 0) score -= 25;
        double symbolRatio = 1.0 - (double) (letters + digits + spaces + cjk) / len;
        if (symbolRatio > 0.6) score -= 20;

        return clamp(score);
    }

    static boolean isMostlyPrintable(String s) {
        if (s == null || s.isEmpty()) return false;
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 0x20 && c < 0x7F) || Character.isWhitespace(c)
                    || (c >= 0x4E00 && c <= 0x9FFF)) {
                printable++;
            }
        }
        return printable >= s.length() * 0.9;
    }

    /** 形如 Base64 / Hex 的串，即使本身可打印也值得试一次 */
    static boolean looksEncoded(String s) {
        if (s.length() < 12) return false;
        if (s.matches("^[A-Za-z0-9+/]{12,}={0,2}$")) return true;
        return s.matches("^[0-9a-fA-F]{16,}$");
    }

    private static Finding better(Finding a, Finding b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.confidence >= b.confidence ? a : b;
    }

    private static int clamp(int v) {
        return Math.max(0, Math.min(100, v));
    }

    /** 供 MCP / 导出使用的文本格式 */
    public static String format(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) return "没有发现明显的加密/编码字符串。";
        StringBuilder sb = new StringBuilder();
        sb.append("发现 ").append(findings.size()).append(" 条可疑字符串\n\n");
        for (Finding f : findings) {
            sb.append("[").append(f.confidence).append("%] ").append(f.method);
            if (!"-".equals(f.key)) sb.append(" key=").append(f.key);
            sb.append("  @0x").append(String.format(Locale.US, "%X", f.virtualAddress)).append('\n');
            sb.append("  原文: ").append(truncate(f.original, 96)).append('\n');
            sb.append("  结果: ").append(truncate(f.result, 160)).append("\n\n");
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        String clean = s.replace('\n', ' ').replace('\r', ' ');
        return clean.length() <= max ? clean : clean.substring(0, max) + "...";
    }
}

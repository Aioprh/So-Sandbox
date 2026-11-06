package com.example.anative.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ARM32（A32 + T32/Thumb-2）函数发现器。
 *
 * <p>AArch64 的定长 4 字节指令可以让扫描器按固定步长遍历；ARM32 不一样：
 * 同一段代码里 ARM 与 Thumb 可以混排（ARMv7 起 interworking 很常见），
 * 指令长度 2 或 4 字节，且没有统一的"函数对齐"约定。因此这里采用
 * 启发式扫描，优先级从高到低：
 *
 * <ol>
 *   <li>符号表已给出的函数（调用方无需再发现）</li>
 *   <li>序言特征：{@code push {..., lr}} / {@code stmdb sp!, {..., lr}} /
 *       {@code sub sp, #imm} 后紧跟 {@code str lr, [sp, #imm]}
 *       / Thumb-2 的 {@code push.w {..., lr}}</li>
 *   <li>被 BL / BLX 引用且命中次数达到阈值的地址</li>
 * </ol>
 *
 * <p>宁可少报不可多报：误判出来的"函数"会污染函数列表和调用图，
 * 而漏掉的函数在"最大覆盖"模式下还有第二轮 BL 传播可以补回来。
 */
public final class Arm32Scanner {

    private Arm32Scanner() {
    }

    /** 单次扫描结果 */
    public static final class ScanResult {
        /** 新发现的函数起始虚拟地址（已去掉 Thumb 位） */
        public final List<Long> starts = new ArrayList<>();
        /** 起始地址 → 是否 Thumb 代码 */
        public final Map<Long, Boolean> thumbFlags = new HashMap<>();
        /** 起始地址 → 估算大小 */
        public final Map<Long, Integer> sizes = new HashMap<>();
    }

    /**
     * 扫描一个可执行段。
     *
     * @param code        段内容（文件偏移对应的字节）
     * @param segStart    段起始虚拟地址
     * @param segEnd      段结束虚拟地址（不含）
     * @param knownOffsets 已知函数地址，命中的地址不会重复返回
     * @param aggressive  最大覆盖模式：降低 BL 命中阈值、放宽序言判定
     */
    public static ScanResult scanSegment(byte[] code, long segStart, long segEnd,
                                         Set<Long> knownOffsets, boolean aggressive) {
        ScanResult result = new ScanResult();
        if (code == null || code.length < 4 || segEnd <= segStart) return result;

        int limit = Math.min(code.length, (int) Math.min(segEnd - segStart, 32L * 1024 * 1024));

        // 1) 收集 BL/BLX 目标及命中次数
        Map<Long, Integer> callTargets = new HashMap<>();
        collectCallTargets(code, limit, segStart, callTargets);

        // 2) 序言扫描
        Set<Long> candidates = new HashSet<>();
        Set<Long> thumbCandidates = new HashSet<>();

        for (int off = 0; off + 4 <= limit; off += 2) {
            long va = segStart + off;
            if ((va & 1) != 0) continue; // Thumb 状态下地址可为奇数，但文件里一律对齐

            // Thumb-16: push {..., lr} → 0xB5xx
            int hw = u16(code, off);
            if ((hw & 0xFF00) == 0xB500 && (hw & 0x00FF) != 0) {
                if (looksLikeThumbPrologue(code, off, limit)) {
                    candidates.add(va);
                    thumbCandidates.add(va);
                }
                continue;
            }
            // Thumb-32: push.w {..., lr} → E92D 4xxx
            if (hw == 0xE92D && off + 4 <= limit) {
                int hw2 = u16(code, off + 2);
                if ((hw2 & 0x4000) != 0) {
                    candidates.add(va);
                    thumbCandidates.add(va);
                    continue;
                }
            }
            // Thumb-16: sub sp, #imm → B08x，紧跟一条 str rX,[sp,#imm] 才算序言。
            // 但 push {..,lr} 之后常常紧跟 sub sp/str，那是同一个函数的序言序列，
            // 不能把 sub sp 当成新函数头
            if ((hw & 0xFF80) == 0xB080 && off + 4 <= limit && !precededByPush(code, off)) {
                int hw2 = u16(code, off + 2);
                if ((hw2 & 0xF800) == 0x9000) {
                    candidates.add(va);
                    thumbCandidates.add(va);
                    continue;
                }
            }
            // ARM: stmdb sp!, {..., lr} → E92D 4xxx（同一编码，需靠上下文区分）
            int w = i32(code, off);
            if ((w & 0xFFFF4000) == 0xE92D4000) {
                if (looksLikeArmPrologue(code, off, limit)) {
                    candidates.add(va);
                }
                continue;
            }
            // ARM: str lr, [sp, #-4]! → E52DE004
            if (w == 0xE52DE004) {
                candidates.add(va);
                continue;
            }
            // ARM: sub sp, sp, #imm —— 无 push 的局部变量序言，
            // 要求后一条确实在往 [sp] 存东西，避免把栈调整当成函数头
            if ((w & 0xFFFFF000) == 0xE24DD000 && off + 8 <= limit) {
                int next = i32(code, off + 4);
                if ((next & 0xFFF00000) == 0xE5800000           // str rX, [sp, #imm]
                        || (next & 0xFFFFF000) == 0xE24DD000) { // 再次 sub sp
                    candidates.add(va);
                }
            }
        }

        // 3) 高频 BL 目标（可能是无标准序言的叶子函数）
        int threshold = aggressive ? 1 : 2;
        for (Map.Entry<Long, Integer> e : callTargets.entrySet()) {
            long target = e.getKey();
            if (target < segStart || target >= segEnd) continue;
            if (knownOffsets.contains(target) || candidates.contains(target)) continue;
            if (e.getValue() < threshold) continue;
            int toff = (int) (target - segStart);
            if (toff < 0 || toff + 4 > limit) continue;
            if (hasAnyBodyShape(code, toff, limit)) {
                candidates.add(target);
                if (looksThumbAt(code, toff, limit)) thumbCandidates.add(target);
            }
        }

        // 4) 估算大小并过滤
        List<Long> sorted = new ArrayList<>(candidates);
        sorted.sort(Long::compareTo);

        for (int i = 0; i < sorted.size(); i++) {
            long start = sorted.get(i);
            if (start < segStart || start >= segEnd) continue;
            if (knownOffsets.contains(start)) continue;

            long nextStart = (i + 1 < sorted.size()) ? sorted.get(i + 1) : segEnd;
            int off = (int) (start - segStart);
            boolean thumb = thumbCandidates.contains(start);
            int size = estimateSize(code, off, limit, thumb,
                    (int) Math.min(nextStart - start, 65536));

            // 小于一条指令的候选没有意义；4 字节的 push/bx lr 短函数是合法的
            if (size < 4) continue;
            if (size > 32768 && !aggressive) continue;

            result.starts.add(start);
            result.thumbFlags.put(start, thumb);
            result.sizes.put(start, size);
        }
        return result;
    }

    /** 前 4 字节内是否刚出现过 push {..., lr}（Thumb 或 ARM 编码） */
    private static boolean precededByPush(byte[] code, int off) {
        if (off >= 2) {
            int p1 = u16(code, off - 2);
            if ((p1 & 0xFF00) == 0xB500) return true;
        }
        if (off >= 4) {
            int p2 = u16(code, off - 4);
            if ((p2 & 0xFF00) == 0xB500) return true;
            int w = i32(code, off - 4);
            if ((w & 0xFFFF4000) == 0xE92D4000) return true;
        }
        return false;
    }

    /** 判断某地址是否看起来是一条 Thumb 指令流（用于给 BL 目标定指令集） */
    public static boolean guessThumb(byte[] code, long segStart, long addr) {
        int off = (int) (addr - segStart);
        if (off < 0 || off + 4 > code.length) return false;
        return looksThumbAt(code, off, code.length);
    }

    /**
     * 估算函数大小：从 {@code off} 起找第一个函数结尾形态。
     *
     * @param maxSize 上限（由调用方按下一个函数起点算出），&lt;=0 时用 4096
     */
    public static int estimateFunctionSize(byte[] code, int off, boolean thumb, int maxSize) {
        if (code == null || off < 0 || off >= code.length) return 4;
        return estimateSize(code, off, code.length, thumb, maxSize);
    }

    // ------------------------------------------------------------------
    // 交叉引用扫描（供 XRefScanner 在 ARM32 下使用）
    // ------------------------------------------------------------------

    /**
     * 扫描 .text 段中的调用与字符串引用，输出格式与原生
     * {@code scanXRefsFromBytes} 完全一致：
     *
     * <pre>
     * F|instrAddr|targetAddr      // BL / BLX
     * S|instrAddr|stringVAddr     // ldr rX, [pc, #imm] 指向的字面量池
     * </pre>
     *
     * 地址一律用十六进制且不带 0x 前缀。
     *
     * @param code        .text 段字节
     * @param base        .text 段虚拟地址
     * @param stringTable "addr|str|..." 形式的字符串表，可为 null
     */
    public static String scanXrefs(byte[] code, long base, String stringTable) {
        if (code == null || code.length < 4) return "";

        Set<Long> stringAddrs = parseStringTable(stringTable);
        StringBuilder sb = new StringBuilder(1 << 16);
        int limit = code.length;

        // ARM BL / BLX
        for (int off = 0; off + 4 <= limit; off += 4) {
            int w = i32(code, off);
            if ((w & 0x0F000000) != 0x0B000000) continue;
            int imm24 = w & 0x00FFFFFF;
            if ((imm24 & 0x00800000) != 0) imm24 |= 0xFF000000;
            long instrVa = base + off;
            long target = instrVa + 8L + ((long) imm24 << 2);
            // 目标必须落在本段内，否则就是 VFP/数据被误当成 BL
            if (target < base || target >= base + limit) continue;
            sb.append('F').append('|')
                    .append(Long.toHexString(instrVa)).append('|')
                    .append(Long.toHexString(target)).append('\n');
        }

        // Thumb BL / BLX
        for (int off = 0; off + 4 <= limit; off += 2) {
            int hw1 = u16(code, off);
            if ((hw1 & 0xF800) != 0xF000) continue;
            int hw2 = u16(code, off + 2);
            if ((hw2 & 0xC000) != 0xC000) continue;
            boolean bl = (hw2 & 0x1000) != 0;
            int s = (hw1 >> 10) & 1;
            int j1 = (hw2 >> 13) & 1;
            int j2 = (hw2 >> 11) & 1;
            int i1 = 1 - (j1 ^ s);
            int i2 = 1 - (j2 ^ s);
            int offset = (s << 24) | (i1 << 23) | (i2 << 22)
                    | ((hw1 & 0x03FF) << 12) | ((hw2 & 0x07FF) << 1);
            if (s != 0) offset |= 0xFE000000;
            long instrVa = base + off;
            long target = (instrVa + 4L + offset) & (bl ? ~1L : ~3L);
            if (target < base || target >= base + limit) continue;
            sb.append('F').append('|')
                    .append(Long.toHexString(instrVa)).append('|')
                    .append(Long.toHexString(target)).append('\n');
        }

        // 字符串引用：ldr rX, [pc, #imm] → 字面量池里存的是地址
        if (!stringAddrs.isEmpty()) {
            for (int off = 0; off + 4 <= limit; off += 4) {
                collectLiteralStringRef(code, off, base, stringAddrs, sb, false);
            }
            // Thumb 的 ldr 是 16 位编码，单独扫
            for (int off = 0; off + 2 <= limit; off += 2) {
                int hw = u16(code, off);
                if ((hw & 0xF800) != 0x4800) continue; // LDR (literal), Rt 在低 3 位
                long pc = (base + off + 4) & ~3L;
                long litAddr = pc + (hw & 0xFF) * 4L;
                long litOff = litAddr - base;
                if (litOff < 0 || litOff + 4 > limit) continue;
                long ptr = i32(code, (int) litOff) & 0xFFFFFFFFL;
                if (stringAddrs.contains(ptr)) {
                    sb.append('S').append('|')
                            .append(Long.toHexString(base + off)).append('|')
                            .append(Long.toHexString(ptr)).append('\n');
                }
            }
        }
        return sb.toString();
    }

    /** ARM 的 ldr rX, [pc, #imm]：imm 为无符号偏移，PC = 当前 + 8 */
    private static void collectLiteralStringRef(byte[] code, int off, long base,
                                                Set<Long> stringAddrs, StringBuilder sb,
                                                boolean unused) {
        int w = i32(code, off);
        // cond != 1111, 010 P U B W L Rn，Rn == PC(15)
        if ((w & 0x0F000000) == 0x0F000000) return;
        if ((w & 0x0C000000) != 0x04000000) return; // 单寄存器 load/store
        if ((w & 0x000F0000) != 0x000F0000) return; // Rn = PC
        if ((w & 0x00100000) == 0) return;          // L 位必须为 1（load）
        boolean add = (w & 0x00800000) != 0;
        int imm12 = w & 0x0FFF;
        long pc = base + off + 8;
        long litAddr = add ? pc + imm12 : pc - imm12;
        long litOff = litAddr - base;
        if (litOff < 0 || litOff + 4 > code.length) return;
        long ptr = i32(code, (int) litOff) & 0xFFFFFFFFL;
        if (stringAddrs.contains(ptr)) {
            sb.append('S').append('|')
                    .append(Long.toHexString(base + off)).append('|')
                    .append(Long.toHexString(ptr)).append('\n');
        }
    }

    private static Set<Long> parseStringTable(String table) {
        Set<Long> set = new HashSet<>();
        if (table == null || table.isEmpty()) return set;
        String[] parts = table.split("\\|");
        // 偶数位是地址，奇数位是字符串内容（内容里可能含 | ，因此只按位置取）
        for (int i = 0; i + 1 < parts.length; i += 2) {
            try {
                set.add(Long.parseLong(parts[i], 16));
            } catch (NumberFormatException ignored) {
            }
        }
        return set;
    }

    // ------------------------------------------------------------------
    // BL / BLX 目标收集
    // ------------------------------------------------------------------

    private static void collectCallTargets(byte[] code, int limit, long base,
                                           Map<Long, Integer> out) {
        // ARM BL: cond=1110 1011 imm24（固定 4 字节对齐）
        for (int off = 0; off + 4 <= limit; off += 4) {
            int w = i32(code, off);
            if ((w & 0x0F000000) == 0x0B000000) {
                int imm24 = w & 0x00FFFFFF;
                if ((imm24 & 0x00800000) != 0) imm24 |= 0xFF000000;
                long target = base + off + 8L + ((long) imm24 << 2);
                if ((target & 3) == 0) bump(out, target);
            }
        }
        // Thumb BL / BLX: 32 位编码，起始于 2 字节边界
        for (int off = 0; off + 4 <= limit; off += 2) {
            int hw1 = u16(code, off);
            if ((hw1 & 0xF800) != 0xF000) continue;
            int hw2 = u16(code, off + 2);
            if ((hw2 & 0xC000) != 0xC000) continue;
            // BL: 11110 S imm10 | 11 J1 1 J2 imm11
            boolean bl = (hw2 & 0x1000) != 0;
            int s = (hw1 >> 10) & 1;
            int j1 = (hw2 >> 13) & 1;
            int j2 = (hw2 >> 11) & 1;
            int i1 = 1 - (j1 ^ s);
            int i2 = 1 - (j2 ^ s);
            int imm10 = hw1 & 0x03FF;
            int imm11 = hw2 & 0x07FF;
            int offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
            if (s != 0) offset |= 0xFE000000;
            long target = base + off + 4L + offset;
            if (bl) {
                bump(out, target & ~1L);
            } else {
                // BLX imm：目标切换到 ARM，地址按 4 对齐
                bump(out, target & ~3L);
            }
        }
    }

    private static void bump(Map<Long, Integer> map, long key) {
        map.put(key, map.getOrDefault(key, 0) + 1);
    }

    // ------------------------------------------------------------------
    // 序言 / 函数体形态判定
    // ------------------------------------------------------------------

    private static boolean looksLikeThumbPrologue(byte[] code, int off, int limit) {
        // push {..., lr} 之后不应该紧跟着另一个 push {..., lr}
        if (off + 4 <= limit) {
            int next = u16(code, off + 2);
            if ((next & 0xFF00) == 0xB500) return false;
        }
        return true;
    }

    private static boolean looksLikeArmPrologue(byte[] code, int off, int limit) {
        // ARM 指令必须 4 字节对齐；Thumb-2 的 push.w 也长这样，靠对齐和后续指令区分
        if ((off & 3) != 0) return false;
        // 紧跟一条 0xE1A0xxxx（mov）或 0xE24DD0xx（sub sp）是典型的 ARM 序言
        if (off + 8 <= limit) {
            int next = i32(code, off + 4);
            if ((next & 0xFFFFF000) == 0xE24DD000) return true;   // sub sp, sp, #imm
            if ((next & 0xFFF00000) == 0xE1A00000) return true;   // mov
            if ((next & 0x0F000000) == 0x0B000000) return true;   // bl
            if ((next & 0xFFFF0000) == 0xE59F0000) return true;   // ldr rX, [pc, #]
        }
        return false;
    }

    /** 目标地址处是否有"像函数体"的指令（用于无标准序言的叶子函数） */
    private static boolean hasAnyBodyShape(byte[] code, int off, int limit) {
        if (off + 4 > limit) return false;
        int hw = u16(code, off);
        // 全 0 或全 F 通常是填充/字面量池
        if (hw == 0x0000 || hw == 0xFFFF) return false;
        int w = i32(code, off);
        if (w == 0x00000000 || w == 0xFFFFFFFF) return false;
        // Thumb: bx lr 开头的小函数（0x4770）
        if (hw == 0x4770) return true;
        // ARM: bx lr（0xE12FFF1E）或 mov pc, lr
        if (w == 0xE12FFF1E || w == 0xE1A0F00E) return true;
        // 更常见的情况：前 32 字节内出现 push/pop/bx lr 之一
        for (int p = off; p + 2 <= limit && p < off + 32; p += 2) {
            int h = u16(code, p);
            if ((h & 0xFF00) == 0xB500) return true;   // Thumb push {.., lr}
            if (h == 0x4770) return true;              // Thumb bx lr
            if (h == 0xE92D) return true;              // Thumb-2 push.w
            if (p + 4 <= limit) {
                int word = i32(code, p);
                if (word == 0xE12FFF1E) return true;                 // ARM bx lr
                if ((word & 0xFFFF8000) == 0xE8BD8000) return true;  // ARM pop {.., pc}
            }
        }
        return false;
    }

    private static boolean looksThumbAt(byte[] code, int off, int limit) {
        // Thumb 函数绝大多数以 push {..,lr} / sub sp / bx lr 开头
        if (off + 4 > limit) return false;
        int hw = u16(code, off);
        if ((hw & 0xFF00) == 0xB500) return true;
        if (hw == 0x4770) return true;
        if (hw == 0xB080 || (hw & 0xFF80) == 0xB080) return true; // sub sp, #imm
        if (hw == 0xE92D) return true;
        // ARM 版 push 是 E92D 4xxx，这里用"低半字是否 4xxx"再判一次
        if (hw == 0xE92D && (u16(code, off + 2) & 0x4000) != 0) return true;
        return false;
    }

    // ------------------------------------------------------------------
    // 大小估算
    // ------------------------------------------------------------------

    /**
     * 从函数头往后找第一个"终止形态"：
     * pop {..., pc} / bx lr / 无条件 b / 明显的数据填充。
     */
    private static int estimateSize(byte[] code, int off, int limit, boolean thumb, int maxSize) {
        int cap = Math.min(maxSize <= 0 ? 4096 : maxSize, limit - off);
        cap = Math.min(cap, 16384);
        int end = Math.min(off + cap, limit);

        for (int p = off; p + 2 <= end; p += 2) {
            int hw = u16(code, p);
            // Thumb: pop {..., pc}
            if ((hw & 0xFF00) == 0xBD00) return p + 2 - off;
            // Thumb: bx lr / blx lr
            if (hw == 0x4770) return p + 2 - off;
            // Thumb-32: pop.w {..., pc} → E8BD 8xxx
            if (hw == 0xE8BD && p + 4 <= end) {
                int hw2 = u16(code, p + 2);
                if ((hw2 & 0x8000) != 0) return p + 4 - off;
            }
            if (!thumb && (p & 3) == 0) {
                int w = i32(code, p);
                if ((w & 0xFFFF0000) == 0xE8BD0000 && (w & 0x8000) != 0) return p + 4 - off; // ldmia sp!, {...,pc}
                if (w == 0xE12FFF1E) return p + 4 - off;   // bx lr
                if (w == 0xE1A0F00E) return p + 4 - off;   // mov pc, lr
                // 无条件 b 既可能是尾调用也可能是循环，不能当函数结尾
                if (w == 0x00000000) return Math.max(4, p - off);        // 填充开始
            }
        }
        return Math.max(4, end - off);
    }

    private static int u16(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    private static int i32(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8)
                | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
    }
}

package com.example.anative.core;

/**
 * 静态反汇编的统一入口。
 *
 * <p>上层（UI / MCP）只关心"给我这段字节的汇编"，不需要知道背后是
 * AArch64 还是 ARM32、是 ARM 还是 Thumb。这个类负责：
 * <ol>
 *   <li>按 SO 架构选择 Capstone 通道</li>
 *   <li>ARM32 下确定指令集（优先用符号表给的 Thumb 标记，其次按首字猜测）</li>
 *   <li>猜错时自动换另一种指令集重试一次</li>
 * </ol>
 */
public final class DisasmBridge {

    private DisasmBridge() {
    }

    /**
     * @param soPath     SO 路径，用于架构探测；为 null 时按 AArch64 处理
     * @param bytes      函数机器码
     * @param offset     函数虚拟偏移（输出里的地址基址）
     * @param size       反汇编长度
     * @param thumbHint  已知的 Thumb 标记（来自符号表）
     * @return 汇编文本；失败返回以 "ERR" 开头的字符串
     */
    public static String disassembleStatic(String soPath, byte[] bytes, long offset, long size,
                                           boolean thumbHint,
                                           String stringTable, String pltTable, String funcTable) {
        ElfArch arch = soPath == null ? ElfArch.UNKNOWN : ElfArch.detect(soPath);
        if (!arch.isArm32()) {
            return NativeInvoker.disassembleBytes(bytes, offset, size, stringTable, pltTable, funcTable);
        }

        boolean thumb = thumbHint || guessThumb(bytes);
        String out = NativeInvoker.disassembleBytesArm32(
                bytes, offset, size, thumb, stringTable, pltTable, funcTable);

        // Capstone 在错误的指令集上通常直接返回 0 条指令，我们换另一种再试一次
        if (looksLikeDecodeFailure(out)) {
            String alt = NativeInvoker.disassembleBytesArm32(
                    bytes, offset, size, !thumb, stringTable, pltTable, funcTable);
            if (alt != null && !looksLikeDecodeFailure(alt)) {
                return alt;
            }
        }
        return out;
    }

    /** 是否应当按 Thumb 解码（仅看首字，命中率约 90%，失败会自动回退） */
    public static boolean guessThumb(byte[] bytes) {
        if (bytes == null || bytes.length < 2) return false;
        int hw = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8);
        // ARM 指令的高半字是 0xE92D/0xE52D 时，首半字可能是 0x4BF0 这类值，
        // 会和 Thumb 的 ldr-literal（0x48xx）撞车，必须先排除
        if (bytes.length >= 4) {
            int hw2 = (bytes[2] & 0xFF) | ((bytes[3] & 0xFF) << 8);
            if (hw2 == 0xE92D || hw2 == 0xE52D) return false;
        }
        // 常见 Thumb 序言
        if ((hw & 0xFF00) == 0xB500) return true;   // push {rX, lr}
        if (hw == 0x4770) return true;              // bx lr（极短函数）
        if ((hw & 0xFF80) == 0xB080) return true;   // sub sp, #imm
        if (hw == 0xE92D) return true;              // push.w
        if ((hw & 0xF800) == 0x4800) return true;   // ldr rX, [pc, #]
        // ARM 版 push 的第二个半字通常是 0x4xxx，首字 0xE92D 已在上方处理
        return false;
    }

    private static boolean looksLikeDecodeFailure(String s) {
        if (s == null || s.isEmpty()) return true;
        if (s.startsWith("ERR")) return true;
        return s.contains("无法按") && s.contains("解码");
    }
}

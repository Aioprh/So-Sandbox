package com.example.anative.core;

import java.io.RandomAccessFile;

/**
 * ELF 架构探测。
 *
 * <p>只读取 ELF header 的前 64 字节，不依赖 jelf，因此即使文件头损坏或
 * 是不受支持的架构也能安全返回 {@link #UNKNOWN}。
 *
 * <p>用于决定后续走哪条分析通道：
 * <ul>
 *   <li>ELF64 + EM_AARCH64 → Capstone AArch64</li>
 *   <li>ELF32 + EM_ARM     → Capstone ARM / Thumb</li>
 *   <li>其他                → 仅符号与段信息，反汇编不可用</li>
 * </ul>
 */
public final class ElfArch {

    public static final int EM_386 = 3;
    public static final int EM_ARM = 40;
    public static final int EM_X86_64 = 62;
    public static final int EM_AARCH64 = 183;

    /** ELFCLASS64 = 2, ELFCLASS32 = 1 */
    public final boolean elf64;
    /** e_machine */
    public final int machine;
    public final boolean littleEndian;
    /** e_flags，ARM 上用于判断 EABI 版本 / 浮点 ABI */
    public final int flags;
    /** 文件是否被成功识别为 ELF */
    public final boolean valid;

    private ElfArch(boolean valid, boolean elf64, int machine, boolean littleEndian, int flags) {
        this.valid = valid;
        this.elf64 = elf64;
        this.machine = machine;
        this.littleEndian = littleEndian;
        this.flags = flags;
    }

    public static final ElfArch UNKNOWN =
            new ElfArch(false, true, EM_AARCH64, true, 0);

    /**
     * 探测文件架构。任何 IO 异常或非法魔数都返回 {@link #UNKNOWN}，不抛异常，
     * 便于在 UI 线程之外无脑调用。
     */
    public static ElfArch detect(String soPath) {
        if (soPath == null) return UNKNOWN;
        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            byte[] h = new byte[64];
            int n = raf.read(h);
            if (n < 20) return UNKNOWN;
            if (h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F') return UNKNOWN;

            boolean elf64 = h[4] == 2;
            boolean le = h[5] != 2;
            int machine = le ? u16le(h, 18) : u16be(h, 18);
            int flags = 0;
            int flagOff = elf64 ? 48 : 36;
            if (n >= flagOff + 4) {
                flags = le ? i32le(h, flagOff) : i32be(h, flagOff);
            }
            return new ElfArch(true, elf64, machine, le, flags);
        } catch (Exception e) {
            return UNKNOWN;
        }
    }

    /** 32 位 ARM（armeabi-v7a / armeabi） */
    public boolean isArm32() {
        return valid && !elf64 && machine == EM_ARM;
    }

    /** 64 位 ARM（arm64-v8a） */
    public boolean isAarch64() {
        return valid && elf64 && machine == EM_AARCH64;
    }

    /** 当前构建能否反汇编该架构 */
    public boolean isDisassemblable() {
        return isArm32() || isAarch64();
    }

    /** 该 SO 是否可以尝试 dlopen 进本进程（32 位进程无法加载 64 位 SO，反之亦然） */
    public boolean matchesProcess() {
        String proc = System.getProperty("os.arch", "");
        boolean proc64 = proc.contains("64");
        return elf64 == proc64;
    }

    public String abi() {
        if (!valid) return "unknown";
        if (isAarch64()) return "arm64-v8a";
        if (isArm32()) return "armeabi-v7a";
        if (machine == EM_386) return "x86";
        if (machine == EM_X86_64) return "x86_64";
        return "machine-" + machine;
    }

    /** 面向用户的简短描述，例如 "ARM32 · armeabi-v7a · 小端" */
    public String describe() {
        if (!valid) return "非 ELF 文件";
        return String.format("%s · %s · %s",
                elf64 ? "ELF64" : "ELF32", abi(), littleEndian ? "小端" : "大端");
    }

    /** ARM EABI 浮点 ABI 描述，仅 ARM32 有意义 */
    public String armFloatAbi() {
        if (!isArm32()) return "";
        int abi = flags & 0x600; // EF_ARM_ABI_FLOAT_SOFT=0x200, HARD=0x400
        if (abi == 0x400) return "hard-float";
        if (abi == 0x200) return "soft-float";
        return "";
    }

    @Override
    public String toString() {
        return describe();
    }

    private static int u16le(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    private static int u16be(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    private static int i32le(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8)
                | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
    }

    private static int i32be(byte[] b, int o) {
        return ((b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16)
                | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }
}

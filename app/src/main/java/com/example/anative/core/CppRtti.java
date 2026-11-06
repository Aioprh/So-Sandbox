package com.example.anative.core;

import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * C++ RTTI / 虚函数表还原。
 *
 * <p>Itanium ABI 下每个多态类都有三个配套符号：
 * <pre>
 *   _ZTV&lt;code&gt;   vtable 本体
 *   _ZTI&lt;code&gt;   type_info
 *   _ZTS&lt;code&gt;   type_info 里的名字字符串
 * </pre>
 * vtable 布局：`[offset-to-top][typeinfo*][虚函数0][虚函数1]...`。
 *
 * <p>难点在于 PIE 的 .data.rel.ro 里这些槽位在文件里是 0，真实值写在
 * .rela.dyn 的 addend 里，所以必须先建重定位表再读槽位。
 */
public final class CppRtti {
    private static final String TAG = "CppRtti";

    private static final int R_AARCH64_RELATIVE = 1027;
    private static final int R_AARCH64_ABS64 = 257;
    private static final int R_AARCH64_GLOB_DAT = 1025;
    private static final int R_AARCH64_JUMP_SLOT = 1026;

    private static final int R_ARM_RELATIVE = 23;
    private static final int R_ARM_ABS32 = 2;
    private static final int R_ARM_GLOB_DAT = 21;
    private static final int R_ARM_JUMP_SLOT = 22;

    /** 单个虚函数槽 */
    public static final class VirtualFunction {
        public final int index;
        public final long targetVa;
        public String targetName;
        public boolean codePointer;

        VirtualFunction(int index, long targetVa) {
            this.index = index;
            this.targetVa = targetVa;
        }

        public String display() {
            if (targetName != null && !targetName.isEmpty()) return targetName;
            return String.format("sub_%X", targetVa);
        }
    }

    /** 一个多态类 */
    public static final class RttiClass {
        public final String code;
        public String className;
        public long vtableVa;
        public long typeinfoVa;
        public String baseClass;
        public final List<VirtualFunction> slots = new ArrayList<>();
        /** vtable 里的槽位有些不是代码指针（RTTI 头、偏移调整 thunk），单独计数 */
        public int codeSlotCount;

        RttiClass(String code) {
            this.code = code;
            this.className = CppRtti.parseTypeName(code);
        }

        public int virtualCount() {
            return slots.size();
        }
    }

    public static final class Result {
        public final List<RttiClass> classes = new ArrayList<>();
        public int totalVtableSymbols;
        public int skipped;
        public String note;
    }

    // ---- 实例状态 ----
    private final String soPath;
    private final int ptrSize;
    private final boolean is64;
    private final byte[] data;              // 整文件镜像（超过 128MB 时为 null）
    private final RandomAccessFile raf;
    private final List<long[]> loads = new ArrayList<>();
    private final Map<Long, Long> relocBySlot = new HashMap<>();
    private long[] dynsymValue = new long[0];
    private int[] dynsymShndx = new int[0];

    private CppRtti(String soPath, int ptrSize, boolean is64, byte[] data, RandomAccessFile raf) {
        this.soPath = soPath;
        this.ptrSize = ptrSize;
        this.is64 = is64;
        this.data = data;
        this.raf = raf;
    }

    /**
     * 扫描 SO 中的全部虚表。
     *
     * @param functions 已解析的函数表，用于把槽位地址翻译成函数名
     */
    public static Result scan(String soPath, List<NativeFunction> functions) throws IOException {
        File f = new File(soPath);
        if (!f.isFile()) throw new IOException("文件不存在: " + soPath);

        ElfArch arch = ElfArch.detect(soPath);
        int ptrSize = arch.elf64 ? 8 : 4;
        boolean is64 = arch.elf64;

        byte[] data = null;
        RandomAccessFile raf = null;
        try {
            if (f.length() <= 128L * 1024 * 1024) {
                data = readFile(f);
            } else {
                raf = new RandomAccessFile(f, "r");
            }
            CppRtti scanner = new CppRtti(soPath, ptrSize, is64, data, raf);
            return scanner.doScan(functions);
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private Result doScan(List<NativeFunction> functions) throws IOException {
        Result result = new Result();

        List<ElfParser.SymbolInfo> symbols = ElfParser.parseSymbols(soPath);
        List<ElfParser.SectionInfo> sections = ElfParser.parseSections(soPath);

        // 函数地址 → 名字。ARM32 的 Thumb 位要清掉再比对
        Map<Long, String> funcByVa = new HashMap<>();
        for (NativeFunction fn : functions) {
            long va = fn.getOffset();
            funcByVa.put(va, fn.getDemangledName() != null ? fn.getDemangledName() : fn.getName());
        }

        Map<Long, String> typeNameByVa = new LinkedHashMap<>();
        Map<String, Long> typeNameByCode = new HashMap<>();
        // symtab 与 dynsym 会给出同一个 _ZTV，按地址去重
        Map<Long, ElfParser.SymbolInfo> vtableByVa = new LinkedHashMap<>();

        for (ElfParser.SymbolInfo sym : symbols) {
            if (sym.name.startsWith("_ZTV")) {
                // value==0 的是未定义的 __cxxabiv1 库内 vtable 引用，不是本库的类
                if (sym.value != 0 && !vtableByVa.containsKey(sym.value)) {
                    vtableByVa.put(sym.value, sym);
                }
            } else if (sym.name.startsWith("_ZTS")) {
                typeNameByVa.put(sym.value, sym.name);
                typeNameByCode.put(sym.name.substring(4), sym.value);
            } else if (sym.name.startsWith("_ZTI")) {
                // 仅用于后面判断基类指针是否真的指向 typeinfo
                typeNameByVa.put(sym.value, sym.name);
            }
        }
        List<ElfParser.SymbolInfo> vtables = new ArrayList<>(vtableByVa.values());
        result.totalVtableSymbols = vtables.size();
        if (vtables.isEmpty()) {
            result.note = "未找到 _ZTV 符号：可能被 strip，或该库不含多态类";
            Log.i(TAG, result.note);
            return result;
        }

        // 重定位表：PIE 的 vtable 槽位在文件里是 0，真实值要靠重定位还原。
        // 先读 dynsym，ABS64/GLOB_DAT 的目标 = 符号值 + addend
        loadDynsym(sections);
        loadRelocations(sections);

        long textStart = Long.MAX_VALUE;
        long textEnd = 0;
        for (ElfParser.SectionInfo sec : sections) {
            if ((sec.flags & 0x4) != 0 && sec.size > 0) { // SHF_EXECINSTR
                textStart = Math.min(textStart, sec.virtualAddress);
                textEnd = Math.max(textEnd, sec.virtualAddress + sec.size);
            }
        }

        // vtable 槽位终点：下一个 vtable 符号的地址
        List<Long> vtableAddrs = new ArrayList<>();
        for (ElfParser.SymbolInfo v : vtables) vtableAddrs.add(v.value);
        java.util.Collections.sort(vtableAddrs);

        for (ElfParser.SymbolInfo vtable : vtables) {
            String code = vtable.name.substring(4);
            RttiClass cls = new RttiClass(code);
            cls.vtableVa = vtable.value;

            // vtable[1] 是 typeinfo 指针
            long typeinfoVa = readPtr(vtable.value + ptrSize);
            cls.typeinfoVa = typeinfoVa;

            // 类名优先从 _ZTS 字符串取，取不到就退回 code 自身解析
            Long ztsVa = typeNameByCode.get(code);
            String nameFromString = ztsVa != null ? readCString(ztsVa) : null;
            if (nameFromString != null && !nameFromString.isEmpty()) {
                String parsed = parseTypeName(nameFromString);
                if (parsed != null && !parsed.isEmpty()) cls.className = parsed;
            }

            // 基类：__si_class_type_info 在 name 之后紧跟 base type_info 指针
            if (typeinfoVa != 0) {
                long baseTypeVa = readPtr(typeinfoVa + 2L * ptrSize);
                if (baseTypeVa != 0) {
                    String baseSym = typeNameByVa.get(baseTypeVa);
                    if (baseSym != null && baseSym.startsWith("_ZTI")) {
                        String baseCode = baseSym.substring(4);
                        Long baseZts = typeNameByCode.get(baseCode);
                        String baseStr = baseZts != null ? readCString(baseZts) : null;
                        cls.baseClass = baseStr != null ? parseTypeName(baseStr) : parseTypeName(baseCode);
                    }
                }
            }

            // 虚函数槽从第 2 个指针之后开始
            long slotStart = vtable.value + 2L * ptrSize;
            long slotEnd = Math.min(
                    nextVtableEnd(vtableAddrs, vtable.value),
                    sectionEndFor(vtable.value, sections));
            int index = 0;
            for (long p = slotStart; p + ptrSize <= slotEnd; p += ptrSize, index++) {
                long target = readPtr(p);
                if (target == 0) break;   // vtable 以空槽结尾

                long va = target;
                if (ptrSize == 4 && (va & 1L) != 0) {
                    va &= ~1L;            // ARM32 Thumb 位
                }

                VirtualFunction vf = new VirtualFunction(index, va);
                String fnName = funcByVa.get(va);
                vf.targetName = fnName;
                vf.codePointer = textEnd > textStart && va >= textStart && va < textEnd
                        && va != 0;
                if (vf.codePointer) cls.codeSlotCount++;
                cls.slots.add(vf);
            }

            if (cls.slots.isEmpty()) {
                result.skipped++;
                continue;
            }
            result.classes.add(cls);
        }

        // 虚函数多的排在前面，更像"主要类"
        java.util.Collections.sort(result.classes,
                (a, b) -> b.slots.size() - a.slots.size());

        Log.i(TAG, "RTTI: " + vtables.size() + " vtables, "
                + result.classes.size() + " classes resolved");
        return result;
    }

    private long nextVtableEnd(List<Long> sortedAddrs, long current) {
        for (long addr : sortedAddrs) {
            if (addr > current) return addr;
        }
        // 最后一个 vtable：给它一个合理上限，避免越界读到别的东西
        return current + ptrSize * 512L;
    }

    // ------------------------------------------------------------------
    // 二进制读取
    // ------------------------------------------------------------------

    /** 读 .dynsym，建立 index → (st_value, st_shndx) 映射 */
    private void loadDynsym(List<ElfParser.SectionInfo> sections) {
        for (ElfParser.SectionInfo sec : sections) {
            if (sec.type != 11) continue;   // SHT_DYNSYM
            int entry = is64 ? 24 : 16;
            long count = sec.size / entry;
            if (count <= 0 || count > 500_000L) continue;

            try {
                byte[] buf = read(sec.offset, (int) Math.min(sec.size, 32L * 1024 * 1024));
                long[] values = new long[(int) count];
                int[] shndx = new int[(int) count];
                for (int i = 0; i < count; i++) {
                    int base = i * entry;
                    if (base + entry > buf.length) break;
                    if (is64) {
                        values[i] = readLong(buf, base + 8);
                        shndx[i] = u16(buf, base + 6);
                    } else {
                        values[i] = readInt(buf, base + 4) & 0xFFFFFFFFL;
                        shndx[i] = u16(buf, base + 14);
                    }
                }
                dynsymValue = values;
                dynsymShndx = shndx;
                Log.d(TAG, "dynsym 条目: " + count);
            } catch (Exception e) {
                Log.w(TAG, "读取 dynsym 失败: " + e.getMessage());
            }
        }
    }

    private void loadRelocations(List<ElfParser.SectionInfo> sections) {
        for (ElfParser.SectionInfo sec : sections) {
            boolean isRela = sec.name.startsWith(".rela");
            boolean isRel = sec.name.startsWith(".rel") && !isRela;
            if (!isRela && !isRel) continue;
            if (sec.offset <= 0 || sec.size <= 0) continue;

            int entrySize = isRela ? (is64 ? 24 : 12) : (is64 ? 16 : 8);
            long count = sec.size / entrySize;
            if (count <= 0 || count > 2_000_000L) continue;

            try {
                byte[] buf = read(sec.offset, (int) Math.min(sec.size, 64L * 1024 * 1024));
                for (long i = 0; i < count; i++) {
                    int base = (int) (i * entrySize);
                    if (base + entrySize > buf.length) break;

                    long rOffset;
                    long rInfo;
                    long rAddend = 0;
                    if (is64) {
                        rOffset = readLong(buf, base);
                        rInfo = readLong(buf, base + 8);
                        if (isRela) rAddend = readLong(buf, base + 16);
                    } else {
                        rOffset = readInt(buf, base) & 0xFFFFFFFFL;
                        rInfo = readInt(buf, base + 4) & 0xFFFFFFFFL;
                        if (isRela) rAddend = readInt(buf, base + 8) & 0xFFFFFFFFL;
                    }

                    int type = is64 ? (int) (rInfo & 0xFFFFFFFFL) : (int) (rInfo & 0xFF);
                    int symIdx = is64 ? (int) (rInfo >>> 32) : (int) ((rInfo >>> 8) & 0xFFFFFF);

                    long target;
                    if (isRelative(type)) {
                        if (rAddend == 0) continue;
                        target = rAddend;
                    } else if (isSymbolPointer(type)) {
                        // 链接器把 vtable 槽写成了 "符号 + addend"，符号值在 dynsym 里
                        if (symIdx <= 0 || symIdx >= dynsymValue.length) continue;
                        if (dynsymShndx[symIdx] == 0) continue;  // 外部符号，运行时才定
                        target = dynsymValue[symIdx] + rAddend;
                    } else {
                        continue;
                    }

                    if (target > 0) relocBySlot.put(rOffset, target);
                }
            } catch (Exception e) {
                Log.w(TAG, "解析重定位失败 " + sec.name + ": " + e.getMessage());
            }
        }
        Log.d(TAG, "重定位条目: " + relocBySlot.size());
    }

    private boolean isRelative(int type) {
        return is64 ? type == R_AARCH64_RELATIVE : type == R_ARM_RELATIVE;
    }

    private boolean isSymbolPointer(int type) {
        if (is64) {
            return type == R_AARCH64_ABS64 || type == R_AARCH64_GLOB_DAT
                    || type == R_AARCH64_JUMP_SLOT;
        }
        return type == R_ARM_ABS32 || type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT;
    }

    /** vtable 所在节的结束地址，避免最后一个表读出节外的数据 */
    private long sectionEndFor(long va, List<ElfParser.SectionInfo> sections) {
        for (ElfParser.SectionInfo sec : sections) {
            if (sec.size <= 0) continue;
            if (va >= sec.virtualAddress && va < sec.virtualAddress + sec.size) {
                return sec.virtualAddress + sec.size;
            }
        }
        return va + ptrSize * 256L;
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private long readPtr(long va) {
        Long reloc = relocBySlot.get(va);
        if (reloc != null) return reloc;
        long off = vaToOffset(va);
        if (off < 0) return 0;
        try {
            byte[] buf = read(off, ptrSize);
            if (buf.length < ptrSize) return 0;
            return ptrSize == 8 ? readLong(buf, 0) : (readInt(buf, 0) & 0xFFFFFFFFL);
        } catch (IOException e) {
            return 0;
        }
    }

    private String readCString(long va) {
        long off = vaToOffset(va);
        if (off < 0) return null;
        try {
            byte[] head = read(off, 512);
            int end = 0;
            while (end < head.length && head[end] != 0) end++;
            if (end == 0) return null;
            return new String(head, 0, end, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private byte[] read(long fileOffset, int len) throws IOException {
        if (len <= 0) return new byte[0];
        if (data != null) {
            if (fileOffset < 0 || fileOffset >= data.length) return new byte[0];
            int n = (int) Math.min(len, data.length - fileOffset);
            byte[] out = new byte[n];
            System.arraycopy(data, (int) fileOffset, out, 0, n);
            return out;
        }
        synchronized (this) {
            raf.seek(fileOffset);
            byte[] out = new byte[len];
            int read = 0;
            while (read < len) {
                int r = raf.read(out, read, len - read);
                if (r < 0) break;
                read += r;
            }
            if (read < len) {
                byte[] trimmed = new byte[read];
                System.arraycopy(out, 0, trimmed, 0, read);
                return trimmed;
            }
            return out;
        }
    }

    private long vaToOffset(long va) {
        if (!loadsLoaded) {
            try (RandomAccessFile tmp = new RandomAccessFile(soPath, "r")) {
                loads.addAll(ElfParser.readPtLoad(tmp));
            } catch (Exception e) {
                Log.w(TAG, "读取 PT_LOAD 失败: " + e.getMessage());
            }
            loadsLoaded = true;
        }
        for (long[] load : loads) {
            long pOffset = load[0];
            long pVaddr = load[1];
            long pFilesz = load[2];
            if (va >= pVaddr && va < pVaddr + pFilesz) {
                return pOffset + (va - pVaddr);
            }
        }
        return -1;
    }

    private boolean loadsLoaded = false;

    // ------------------------------------------------------------------
    // 工具函数
    // ------------------------------------------------------------------

    /**
     * 解析 type_info 里的名字字符串，格式是长度前缀：
     * `3Foo` → Foo，`N3ns3FooE` → ns::Foo，`St6vectorIiSaIiEE` → std::vector（模板参数丢弃）。
     */
    static String parseTypeName(String raw) {
        if (raw == null || raw.isEmpty()) return raw;
        int i = 0;
        if (raw.charAt(0) == 'N') {
            i = 1;
        }
        StringBuilder sb = new StringBuilder();
        while (i < raw.length()) {
            char c = raw.charAt(i);
            if (c == 'E') break;
            if (c >= '0' && c <= '9') {
                int len = 0;
                while (i < raw.length() && raw.charAt(i) >= '0' && raw.charAt(i) <= '9') {
                    len = len * 10 + (raw.charAt(i) - '0');
                    i++;
                }
                if (len <= 0 || i + len > raw.length()) break;
                if (sb.length() > 0) sb.append("::");
                sb.append(raw, i, i + len);
                i += len;
            } else if (raw.startsWith("St", i)) {
                if (sb.length() > 0) sb.append("::");
                sb.append("std");
                i += 2;
            } else {
                // 模板实参、函数类型等复杂编码，超出本解析器范围
                break;
            }
        }
        if (sb.length() == 0) return raw;
        return sb.toString();
    }

    private static byte[] readFile(File f) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            byte[] buf = new byte[(int) f.length()];
            raf.readFully(buf);
            return buf;
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

    /** 供 UI 展示的纯文本摘要 */
    public static String summary(Result result) {
        if (result == null || result.classes.isEmpty()) {
            return result != null && result.note != null ? result.note : "没有可还原的虚表";
        }
        int totalSlots = 0;
        for (RttiClass c : result.classes) totalSlots += c.slots.size();
        return String.format(java.util.Locale.US,
                "%d 个类 / %d 个虚函数槽（共 %d 个 _ZTV 符号）",
                result.classes.size(), totalSlots, result.totalVtableSymbols);
    }
}

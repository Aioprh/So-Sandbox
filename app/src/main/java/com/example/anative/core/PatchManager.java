package com.example.anative.core;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * 补丁管理：记录每一次对工作副本的写入，支持撤销 / 重做 / 差异查看。
 *
 * 只在内存中记录当前会话，切换 SO 时自动清空（原始文件始终不变）。
 */
public final class PatchManager {

    public enum Kind {ASM, HEX, BATCH}

    public static final class Patch {
        public final int id;
        public final long fileOffset;
        public final long virtualAddress;
        public final byte[] oldBytes;
        public final byte[] newBytes;
        public final Kind kind;
        public final String description;
        public final long timestamp;
        public boolean undone;

        Patch(int id, long fileOffset, long virtualAddress, byte[] oldBytes, byte[] newBytes,
              Kind kind, String description, long timestamp) {
            this.id = id;
            this.fileOffset = fileOffset;
            this.virtualAddress = virtualAddress;
            this.oldBytes = oldBytes;
            this.newBytes = newBytes;
            this.kind = kind;
            this.description = description;
            this.timestamp = timestamp;
        }

        public String timeText() {
            return new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(timestamp));
        }

        public String addressText() {
            if (virtualAddress > 0) {
                return "0x" + String.format(Locale.US, "%X", virtualAddress);
            }
            return "off 0x" + String.format(Locale.US, "%X", fileOffset);
        }
    }

    private static final PatchManager INSTANCE = new PatchManager();

    private final List<Patch> patches = new ArrayList<>();
    private int nextId = 1;
    private String soPath;

    private PatchManager() {
    }

    public static PatchManager getInstance() {
        return INSTANCE;
    }

    /**
     * 切换 SO 时清空记录；同一路径重复加载不清空。
     */
    public synchronized void resetFor(String path) {
        if (path == null ? soPath == null : path.equals(soPath)) {
            return;
        }
        soPath = path;
        patches.clear();
        nextId = 1;
    }

    /**
     * 写入一段字节并记录补丁。写入失败不会留下记录。
     */
    public synchronized Patch apply(String path, long fileOffset, byte[] data,
                                    Kind kind, String description, long virtualAddress)
            throws IOException {
        if (path == null || path.isEmpty()) {
            throw new IOException("SO 路径为空");
        }
        if (data == null || data.length == 0) {
            throw new IOException("写入数据为空");
        }
        if (fileOffset < 0) {
            throw new IOException("文件偏移非法");
        }
        try (RandomAccessFile raf = new RandomAccessFile(path, "rw")) {
            long length = raf.length();
            if (fileOffset + data.length > length) {
                throw new IOException("写入越界: 0x" + Long.toHexString(fileOffset)
                        + " + " + data.length + " > " + length);
            }
            byte[] old = new byte[data.length];
            raf.seek(fileOffset);
            raf.readFully(old);
            raf.seek(fileOffset);
            raf.write(data);

            Patch patch = new Patch(nextId++, fileOffset, virtualAddress, old, data.clone(),
                    kind, description == null ? "" : description, System.currentTimeMillis());
            patches.add(patch);
            DataHolder.getInstance().markFileModified();
            return patch;
        }
    }

    public synchronized boolean undo(int id) throws IOException {
        Patch patch = find(id);
        if (patch == null || patch.undone) {
            return false;
        }
        writeBytes(patch.fileOffset, patch.oldBytes);
        patch.undone = true;
        if (patch.kind == Kind.ASM && patch.virtualAddress > 0) {
            DataHolder.getInstance().removeModifiedInstruction(patch.virtualAddress);
        }
        return true;
    }

    public synchronized boolean redo(int id) throws IOException {
        Patch patch = find(id);
        if (patch == null || !patch.undone) {
            return false;
        }
        writeBytes(patch.fileOffset, patch.newBytes);
        patch.undone = false;
        return true;
    }

    /**
     * 从新到旧撤销所有补丁，返回撤销条数。
     */
    public synchronized int undoAll() {
        int count = 0;
        for (int i = patches.size() - 1; i >= 0; i--) {
            Patch patch = patches.get(i);
            if (patch.undone) {
                continue;
            }
            try {
                writeBytes(patch.fileOffset, patch.oldBytes);
                patch.undone = true;
                if (patch.kind == Kind.ASM && patch.virtualAddress > 0) {
                    DataHolder.getInstance().removeModifiedInstruction(patch.virtualAddress);
                }
                count++;
            } catch (IOException ignored) {
                // 单条失败不影响其余
            }
        }
        return count;
    }

    public synchronized List<Patch> getPatches() {
        return new ArrayList<>(patches);
    }

    public synchronized int getActiveCount() {
        int count = 0;
        for (Patch patch : patches) {
            if (!patch.undone) {
                count++;
            }
        }
        return count;
    }

    public synchronized int getTotalCount() {
        return patches.size();
    }

    /**
     * 生成可读的补丁差异，供 UI 预览或 MCP 返回。
     */
    public synchronized String diff() {
        if (patches.isEmpty()) {
            return "暂无修改记录。";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("共 ").append(patches.size()).append(" 条修改，生效中 ")
                .append(getActiveCount()).append(" 条\n");
        for (Patch patch : patches) {
            sb.append(String.format(Locale.US, "#%d %s %s  %s", patch.id, patch.addressText(),
                    patch.timeText(), patch.kind));
            if (patch.undone) {
                sb.append(" [已撤销]");
            }
            sb.append('\n');
            if (!patch.description.isEmpty()) {
                sb.append("   ").append(patch.description).append('\n');
            }
            sb.append("   - ").append(toHex(patch.oldBytes)).append('\n');
            sb.append("   + ").append(toHex(patch.newBytes)).append('\n');
        }
        return sb.toString();
    }

    /**
     * 导出为 unified diff 风格文本，便于存档或分享。
     */
    public synchronized String exportPatchText() {
        StringBuilder sb = new StringBuilder();
        sb.append("# SoSandbox patch set\n");
        sb.append("# file: ").append(soPath == null ? "(unknown)" : soPath).append('\n');
        sb.append("# time: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
                .format(new Date())).append("\n\n");
        for (Patch patch : patches) {
            if (patch.undone) {
                continue;
            }
            sb.append(String.format(Locale.US, "@@ %s file=0x%X len=%d @@\n",
                    patch.addressText(), patch.fileOffset, patch.newBytes.length));
            if (!patch.description.isEmpty()) {
                sb.append("# ").append(patch.description).append('\n');
            }
            sb.append("- ").append(toHex(patch.oldBytes)).append('\n');
            sb.append("+ ").append(toHex(patch.newBytes)).append("\n\n");
        }
        return sb.toString();
    }

    private Patch find(int id) {
        for (Patch patch : patches) {
            if (patch.id == id) {
                return patch;
            }
        }
        return null;
    }

    private static void writeBytes(long fileOffset, byte[] data) throws IOException {
        String path = DataHolder.getInstance().getSoPath();
        if (path == null || path.isEmpty()) {
            throw new IOException("SO 路径为空");
        }
        try (RandomAccessFile raf = new RandomAccessFile(path, "rw")) {
            raf.seek(fileOffset);
            raf.write(data);
        }
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 3);
        for (byte b : data) {
            sb.append(String.format(Locale.US, "%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }
}

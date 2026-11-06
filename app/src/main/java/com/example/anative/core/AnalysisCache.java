package com.example.anative.core;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 分析结果磁盘缓存。
 *
 * <p>一个 8MB 的 SO，{@code parseStrings} 要遍历整个可加载段并做编码尝试，
 * 在中端机上是 2-4 秒；每次切页都重算会让工具用起来很难受。这里把
 * 函数表 / 字符串表 / PLT 表序列化到应用缓存目录，用
 * <b>路径 + 文件大小 + 修改时间</b> 作为键：
 *
 * <ul>
 *   <li>同一个文件再次打开直接命中</li>
 *   <li>文件被重新导入（大小或 mtime 变了）自动失效</li>
 *   <li>用户手动编辑 SO（PatchManager 保存）后应调用 {@link #invalidate}</li>
 * </ul>
 *
 * <p>缓存只存"解析结果"，不存反汇编文本——后者体积大且和当前视图相关。
 */
public final class AnalysisCache {

    private static final String TAG = "AnalysisCache";
    private static final int VERSION = 1;

    private static volatile boolean enabled = true;

    private AnalysisCache() {
    }

    public static boolean isEnabled() {
        return enabled;
    }

    public static void setEnabled(boolean value) {
        enabled = value;
    }

    // ------------------------------------------------------------------
    // 对外 API
    // ------------------------------------------------------------------

    public static List<NativeFunction> functions(Context ctx, String soPath, String mode)
            throws IOException {
        List<NativeFunction> cached = readFunctions(ctx, soPath, mode);
        if (cached != null) return cached;

        List<NativeFunction> parsed = ElfParser.parseFunctions(soPath, mode);
        writeAsync(ctx, soPath, mode, "functions", () -> toJsonFunctions(parsed));
        return parsed;
    }

    public static List<ElfParser.StringEntry> strings(Context ctx, String soPath)
            throws IOException {
        List<ElfParser.StringEntry> cached = readStrings(ctx, soPath);
        if (cached != null) return cached;

        List<ElfParser.StringEntry> parsed = ElfParser.parseStrings(soPath);
        writeAsync(ctx, soPath, null, "strings", () -> toJsonStrings(parsed));
        return parsed;
    }

    public static List<PltEntry> plt(Context ctx, String soPath) throws IOException {
        List<PltEntry> cached = readPlt(ctx, soPath);
        if (cached != null) return cached;

        List<PltEntry> parsed = ElfParser.parsePlt(soPath);
        writeAsync(ctx, soPath, null, "plt", () -> toJsonPlt(parsed));
        return parsed;
    }

    /** 手动让某个 SO 的所有缓存失效（补丁保存后调用） */
    public static void invalidate(Context ctx, String soPath) {
        try {
            File dir = cacheDir(ctx);
            String prefix = keyPrefix(soPath);
            File[] files = dir.listFiles();
            if (files == null) return;
            for (File f : files) {
                if (f.getName().startsWith(prefix)) {
                    //noinspection ResultOfMethodCallIgnored
                    f.delete();
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "invalidate failed: " + e.getMessage());
        }
    }

    public static void clear(Context ctx) {
        File[] files = cacheDir(ctx).listFiles();
        if (files == null) return;
        for (File f : files) {
            //noinspection ResultOfMethodCallIgnored
            f.delete();
        }
    }

    public static long sizeBytes(Context ctx) {
        long total = 0;
        File[] files = cacheDir(ctx).listFiles();
        if (files == null) return 0;
        for (File f : files) total += f.length();
        return total;
    }

    public static int entryCount(Context ctx) {
        File[] files = cacheDir(ctx).listFiles();
        return files == null ? 0 : files.length;
    }

    // ------------------------------------------------------------------
    // 读
    // ------------------------------------------------------------------

    private static List<NativeFunction> readFunctions(Context ctx, String soPath, String mode) {
        JSONObject root = read(ctx, soPath, mode, "functions");
        if (root == null) return null;
        try {
            JSONArray arr = root.getJSONArray("items");
            List<NativeFunction> list = new ArrayList<>(arr.length());
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                NativeFunction f = new NativeFunction(
                        o.getString("name"), o.getLong("offset"), o.getLong("size"),
                        o.optString("source", "cache"));
                f.setThumb(o.optBoolean("thumb", false));
                list.add(f);
            }
            Log.i(TAG, "functions cache hit: " + list.size());
            return list;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<ElfParser.StringEntry> readStrings(Context ctx, String soPath) {
        JSONObject root = read(ctx, soPath, null, "strings");
        if (root == null) return null;
        try {
            JSONArray arr = root.getJSONArray("items");
            List<ElfParser.StringEntry> list = new ArrayList<>(arr.length());
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                list.add(new ElfParser.StringEntry(o.getLong("va"), o.getString("value"),
                        o.optString("sec", "")));
            }
            Log.i(TAG, "strings cache hit: " + list.size());
            return list;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<PltEntry> readPlt(Context ctx, String soPath) {
        JSONObject root = read(ctx, soPath, null, "plt");
        if (root == null) return null;
        try {
            JSONArray arr = root.getJSONArray("items");
            List<PltEntry> list = new ArrayList<>(arr.length());
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                list.add(new PltEntry(o.getLong("addr"), o.getLong("size"),
                        o.getString("symbol"), o.getLong("got")));
            }
            Log.i(TAG, "plt cache hit: " + list.size());
            return list;
        } catch (Exception e) {
            return null;
        }
    }

    private static JSONObject read(Context ctx, String soPath, String mode, String kind) {
        if (!enabled || ctx == null || soPath == null) return null;
        File f = cacheFile(ctx, soPath, mode, kind);
        if (!f.isFile()) return null;
        try (InputStream in = new FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int read = 0;
            while (read < buf.length) {
                int n = in.read(buf, read, buf.length - read);
                if (n < 0) break;
                read += n;
            }
            JSONObject root = new JSONObject(new String(buf, 0, read, StandardCharsets.UTF_8));
            if (root.optInt("version") != VERSION) return null;
            return root;
        } catch (Exception e) {
            Log.w(TAG, "cache read failed: " + e.getMessage());
            return null;
        }
    }

    // ------------------------------------------------------------------
    // 写
    // ------------------------------------------------------------------

    private static void writeAsync(Context ctx, String soPath, String mode, String kind,
                                   java.util.function.Supplier<JSONObject> payloadFactory) {
        if (!enabled || ctx == null || soPath == null) return;
        final File target = cacheFile(ctx, soPath, mode, kind);
        // 序列化与写盘都不该阻塞解析返回：几万条字符串转 JSON 也要上百毫秒
        new Thread(() -> {
            try {
                final String content = payloadFactory.get().toString();
                File parent = target.getParentFile();
                if (parent != null && !parent.exists() && !parent.mkdirs()) return;
                try (FileOutputStream out = new FileOutputStream(target)) {
                    out.write(content.getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                Log.w(TAG, "cache write failed: " + e.getMessage());
            }
        }, "analysis-cache-write").start();
    }

    private static JSONObject toJsonFunctions(List<NativeFunction> list) {
        JSONObject root = base();
        JSONArray arr = new JSONArray();
        try {
            for (NativeFunction f : list) {
                JSONObject o = new JSONObject();
                o.put("name", f.getName());
                o.put("offset", f.getOffset());
                o.put("size", f.getSize());
                o.put("source", f.getSource());
                o.put("thumb", f.isThumb());
                arr.put(o);
            }
            root.put("items", arr);
        } catch (Exception ignored) {
        }
        return root;
    }

    private static JSONObject toJsonStrings(List<ElfParser.StringEntry> list) {
        JSONObject root = base();
        JSONArray arr = new JSONArray();
        try {
            for (ElfParser.StringEntry s : list) {
                JSONObject o = new JSONObject();
                o.put("va", s.virtualAddress);
                o.put("value", s.value);
                o.put("sec", s.section);
                arr.put(o);
            }
            root.put("items", arr);
        } catch (Exception ignored) {
        }
        return root;
    }

    private static JSONObject toJsonPlt(List<PltEntry> list) {
        JSONObject root = base();
        JSONArray arr = new JSONArray();
        try {
            for (PltEntry p : list) {
                JSONObject o = new JSONObject();
                o.put("addr", p.offset);
                o.put("size", p.size);
                o.put("symbol", p.symbolName);
                o.put("got", p.gotOffset);
                arr.put(o);
            }
            root.put("items", arr);
        } catch (Exception ignored) {
        }
        return root;
    }

    private static JSONObject base() {
        JSONObject root = new JSONObject();
        try {
            root.put("version", VERSION);
            root.put("created", System.currentTimeMillis());
        } catch (Exception ignored) {
        }
        return root;
    }

    // ------------------------------------------------------------------
    // 键与路径
    // ------------------------------------------------------------------

    private static File cacheDir(Context ctx) {
        File dir = new File(ctx.getCacheDir(), "analysis");
        if (!dir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
        return dir;
    }

    private static File cacheFile(Context ctx, String soPath, String mode, String kind) {
        return new File(cacheDir(ctx), fileName(soPath, mode, kind));
    }

    private static String fileName(String soPath, String mode, String kind) {
        File f = new File(soPath);
        String raw = soPath + "|" + f.length() + "|" + f.lastModified() + "|"
                + (mode == null ? "" : mode) + "|" + kind;
        return keyPrefix(soPath) + "-" + kind + (mode == null ? "" : "-" + mode)
                + "-" + sha1(raw).substring(0, 12) + ".json";
    }

    /** 文件级前缀，用于 invalidate 时批量删除 */
    private static String keyPrefix(String soPath) {
        return sha1(soPath).substring(0, 16);
    }

    private static String sha1(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format(Locale.US, "%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return String.format(Locale.US, "%016x", s.hashCode()).replace('-', '0');
        }
    }
}

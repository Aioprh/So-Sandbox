package com.example.anative.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 轻量库指纹：按导出符号、字符串与节名识别常见框架 / 加固，给分析一个起点。
 * 纯本地规则匹配，不做联网。
 */
public final class LibraryFingerprint {

    public static final class Match {
        public final String name;
        public final String detail;

        Match(String name, String detail) {
            this.name = name;
            this.detail = detail;
        }
    }

    private LibraryFingerprint() {
    }

    public static List<Match> detect(String soPath, List<NativeFunction> functions,
                                     List<ElfParser.StringEntry> strings, List<PltEntry> plt) {
        List<Match> matches = new ArrayList<>();
        StringBuilder names = new StringBuilder();
        StringBuilder stringBlob = new StringBuilder();

        if (functions != null) {
            int limit = Math.min(functions.size(), 4000);
            for (int i = 0; i < limit; i++) {
                NativeFunction function = functions.get(i);
                if (function.getName() != null) {
                    names.append(function.getName().toLowerCase(Locale.US)).append('\n');
                }
            }
        }
        if (plt != null) {
            for (PltEntry entry : plt) {
                if (entry != null && entry.symbolName != null) {
                    names.append(entry.symbolName.toLowerCase(Locale.US)).append('\n');
                }
            }
        }
        if (strings != null) {
            int limit = Math.min(strings.size(), 40000);
            for (int i = 0; i < limit; i++) {
                ElfParser.StringEntry entry = strings.get(i);
                if (entry != null && entry.value != null && entry.value.length() < 200) {
                    stringBlob.append(entry.value.toLowerCase(Locale.US)).append('\n');
                }
            }
        }

        String sectionNames = "";
        try {
            StringBuilder sb = new StringBuilder();
            for (ElfParser.SectionInfo section : ElfParser.parseSections(soPath)) {
                sb.append(section.name == null ? "" : section.name.toLowerCase(Locale.US)).append(' ');
            }
            sectionNames = sb.toString();
        } catch (Exception ignored) {
            // 节表解析失败不影响其余判断
        }

        String all = names.toString() + stringBlob + sectionNames;

        if (all.contains("upx0") || all.contains("upx1") || all.contains("upx!")) {
            matches.add(new Match("UPX", "节名/标记命中，文件可能被 UPX 压缩"));
        }
        if (all.contains("unityplayer") || all.contains("unityengine")
                || all.contains("il2cpp") || all.contains("libunity")) {
            matches.add(new Match("Unity", "IL2CPP / UnityPlayer 特征，重点看 global-metadata 与 il2cpp 导出"));
        }
        if (all.contains("libflutter") || all.contains("flutterengine") || all.contains("dart::")) {
            matches.add(new Match("Flutter", "Dart AOT 运行时，业务逻辑多在 libapp.so"));
        }
        if (all.contains("hermes") || all.contains("facebook::react")) {
            matches.add(new Match("React Native", "Hermes / RN 运行时"));
        }
        if (all.contains("cocos2d") || all.contains("cocos")) {
            matches.add(new Match("Cocos2d-x", "Cocos 引擎"));
        }
        if (all.contains("libjiagu") || all.contains("libdexhelper") || all.contains("libshell")
                || all.contains("libmobisec") || all.contains("libnesec")) {
            matches.add(new Match("加固壳", "命中常见加固库名，真实逻辑可能在运行时解密"));
        }
        if (all.contains("frida") || all.contains("xposed") || all.contains("substrate")) {
            matches.add(new Match("Hook 痕迹", "包含 Frida/Xposed/Substrate 相关字符串"));
        }
        if (!sectionNames.contains(".symtab")) {
            matches.add(new Match("符号已剥离", "节表无 .symtab，函数名多为 sub_*"));
        }
        if (all.contains("obfuscator-llvm") || all.contains("ollvm")) {
            matches.add(new Match("OLLVM", "可能经过控制流平坦化，反编译可读性会明显下降"));
        }
        return matches;
    }

    public static String summary(List<Match> matches) {
        if (matches == null || matches.isEmpty()) {
            return "未识别到常见框架特征";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < matches.size(); i++) {
            if (i > 0) {
                sb.append(" · ");
            }
            sb.append(matches.get(i).name);
        }
        return sb.toString();
    }
}

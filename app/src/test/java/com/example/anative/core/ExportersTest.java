package com.example.anative.core;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ExportersTest {

    private static List<NativeFunction> sampleFunctions() {
        List<NativeFunction> list = new ArrayList<>();
        NativeFunction f1 = new NativeFunction("_ZN3foo3barEi", 0x1000, 32, "dynsym");
        NativeFunction f2 = new NativeFunction("Java_com_example_Main_run", 0x2000, 64, "dynsym");
        list.add(f1);
        list.add(f2);
        return list;
    }

    @Test
    public void sanitizeRemovesNamespaceSeparators() {
        String name = Exporters.sanitize("ns::Foo::bar");
        assertFalse(name.contains(":"));
        assertTrue(name.contains("Foo"));
    }

    @Test
    public void sanitizePrefixesLeadingDigit() {
        assertEquals("f_3abc", Exporters.sanitize("3abc"));
    }

    @Test
    public void sanitizeStripsTemplateBrackets() {
        String name = Exporters.sanitize("foo<int>");
        assertFalse(name.contains("<"));
        assertFalse(name.contains(">"));
    }

    @Test
    public void idaScriptContainsRenameCalls() {
        String script = Exporters.idaPython("libtest.so", sampleFunctions(), 100);
        assertTrue(script.contains("set_name"));
        assertTrue(script.contains("0x1000"));
        assertTrue(script.contains("libtest.so"));
        // 生成的脚本必须是合法 Python 缩进结构
        assertTrue(script.contains("def apply_names():"));
    }

    @Test
    public void ghidraScriptUsesFunctionManager() {
        String script = Exporters.ghidraScript("libtest.so", sampleFunctions(), 100);
        assertTrue(script.contains("createFunction"));
        assertTrue(script.contains("SourceType.USER_DEFINED"));
    }

    @Test
    public void cHeaderHasIncludeGuardAndPrototypes() {
        String header = Exporters.cHeader("libtest.so", sampleFunctions(), null, null);
        assertTrue(header.startsWith("/*"));
        assertTrue(header.contains("#ifndef SO_SANDBOX_"));
        assertTrue(header.contains("_H"));
        assertTrue(header.contains("#endif"));
        assertTrue(header.contains("("));
    }

    @Test
    public void respectsFunctionLimit() {
        String script = Exporters.idaPython("x.so", sampleFunctions(), 1);
        // 只导出 1 个函数时，第二个地址不应出现
        assertFalse(script.contains("0x2000"));
    }

    @Test
    public void emptyNameFallsBackToPlaceholder() {
        assertEquals("sub_unknown", Exporters.sanitize(""));
        assertEquals("sub_unknown", Exporters.sanitize(null));
    }

    @Test
    public void exportDispatchesByFormat() {
        assertTrue(Exporters.export("ghidra", "a.so", sampleFunctions()).contains("createFunction"));
        assertTrue(Exporters.export("cheader", "a.so", sampleFunctions()).contains("#ifndef"));
        assertTrue(Exporters.export("ida", "a.so", sampleFunctions()).contains("set_name"));
    }
}

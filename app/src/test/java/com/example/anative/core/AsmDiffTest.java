package com.example.anative.core;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AsmDiffTest {

    private static final String OLD = ""
            + "1000:  stp x29, x30, [sp, #-16]!\n"
            + "1004:  mov x29, sp\n"
            + "1008:  bl  #0x2000\n"
            + "100c:  add x0, x0, #0x10\n"
            + "1010:  ret\n";

    private static final String NEW = ""
            + "2000:  stp x29, x30, [sp, #-16]!\n"
            + "2004:  mov x29, sp\n"
            + "2008:  bl  #0x3100\n"
            + "200c:  add x0, x0, #0x20\n"
            + "2010:  ret\n";

    @Test
    public void identicalInstructionsHaveNoDiff() {
        AsmDiff.Result r = AsmDiff.diff(OLD, OLD);
        assertEquals(0, r.changeCount());
        assertEquals(5, r.unchanged);
        assertEquals(100, r.similarity());
    }

    @Test
    public void ignoresAddressShiftAndBranchTarget() {
        // 地址整体平移、bl 目标不同 —— 这些都不是真正的代码变化
        AsmDiff.Result r = AsmDiff.diff(OLD, NEW);
        // 只有 add 的立即数变了，其余 4 条应视为相同
        assertEquals(4, r.unchanged);
        assertEquals(1, r.removed);
        assertEquals(1, r.added);
    }

    @Test
    public void keepsImmediateOperandDifferences() {
        assertEquals("add x0, x0, #0x10", AsmDiff.normalize("100c:  add x0, x0, #0x10"));
        assertFalse(AsmDiff.normalize("100c:  add x0, x0, #0x10")
                .equals(AsmDiff.normalize("100c:  add x0, x0, #0x20")));
    }

    @Test
    public void foldsBranchTargets() {
        assertEquals(AsmDiff.normalize("1008: bl #0x2000"),
                AsmDiff.normalize("2008: bl #0x3100"));
    }

    @Test
    public void stripsCommentsBeforeComparing() {
        assertEquals(AsmDiff.normalize("1008: bl #0x2000 ; memcpy@PLT"),
                AsmDiff.normalize("2008: bl #0x3100 ; memcpy@PLT"));
    }

    @Test
    public void skipsHeaderAndBlankLines() {
        List<String> insns = AsmDiff.splitInstructions(
                "; AArch64 Disassembly\n\n1000:  ret\n");
        assertEquals(1, insns.size());
    }

    @Test
    public void handlesInsertion() {
        String withExtra = OLD.replace("1008:  bl  #0x2000\n",
                "1008:  bl  #0x2000\n100a:  nop\n");
        AsmDiff.Result r = AsmDiff.diff(OLD, withExtra);
        assertEquals(1, r.added);
        assertEquals(0, r.removed);
    }

    @Test
    public void renderCollapsesLongRuns() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append(String.format("%x:  nop\n", 0x1000 + i * 4));
        }
        String asm = sb.toString();
        String changed = asm + "1990:  ret\n";
        AsmDiff.Result r = AsmDiff.diff(asm, changed);
        String text = AsmDiff.renderText(r, 2);
        assertTrue(text.contains("条相同指令"));
        assertTrue(text.contains("+ ret"));
    }
}

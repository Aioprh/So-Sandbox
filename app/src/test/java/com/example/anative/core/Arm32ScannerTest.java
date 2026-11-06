package com.example.anative.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

public class Arm32ScannerTest {

    /** 造一段 Thumb 代码：push {r7, lr} / bx lr */
    private static byte[] thumbStub() {
        return new byte[]{
                (byte) 0x80, (byte) 0xB5,   // push {r7, lr}
                (byte) 0x70, (byte) 0x47,   // bx lr
                (byte) 0x00, (byte) 0x00,   // padding
                (byte) 0x00, (byte) 0x00
        };
    }

    @Test
    public void findsThumbPrologue() {
        byte[] code = thumbStub();
        Arm32Scanner.ScanResult r = Arm32Scanner.scanSegment(
                code, 0x1000, 0x1000 + code.length, new HashSet<>(), false);

        assertTrue("应识别出 Thumb 函数起始", r.starts.contains(0x1000L));
        Boolean thumb = r.thumbFlags.get(0x1000L);
        assertNotNull(thumb);
        assertTrue(thumb);
        assertEquals(4, (int) r.sizes.get(0x1000L));
    }

    @Test
    public void skipsKnownOffsets() {
        byte[] code = thumbStub();
        Set<Long> known = new HashSet<>();
        known.add(0x1000L);
        Arm32Scanner.ScanResult r = Arm32Scanner.scanSegment(
                code, 0x1000, 0x1000 + code.length, known, false);
        assertFalse(r.starts.contains(0x1000L));
    }

    @Test
    public void estimatesSizeToReturn() {
        byte[] code = thumbStub();
        int size = Arm32Scanner.estimateFunctionSize(code, 0, true, 0);
        assertEquals(4, size);
    }

    @Test
    public void guessesThumbFromPrologue() {
        assertTrue(DisasmBridge.guessThumb(thumbStub()));
        // ARM 的 push {r4-r11, lr} = 0xE92D4BF0，小端首半字是 0x4BF0 → 不应判成 Thumb
        byte[] arm = new byte[]{(byte) 0xF0, (byte) 0x4B, (byte) 0x2D, (byte) 0xE9};
        assertFalse(DisasmBridge.guessThumb(arm));
        // Thumb-2 的 push.w {r4-r11, lr} = 0xE92D4BF0，首半字 0xE92D
        byte[] thumb2 = new byte[]{(byte) 0x2D, (byte) 0xE9, (byte) 0xF0, (byte) 0x4B};
        assertTrue(DisasmBridge.guessThumb(thumb2));
        assertFalse(DisasmBridge.guessThumb(new byte[]{(byte) 0x1F, (byte) 0x20, (byte) 0x03, (byte) 0xD5}));
    }

    @Test
    public void parsesArmBlXref() {
        // ARM 模式：bl #+8 → 0x0B000002，位于 0x1000，目标 = 0x1000 + 8 + 8 = 0x1010
        byte[] code = new byte[32];
        code[0] = 0x02;
        code[1] = 0x00;
        code[2] = 0x00;
        code[3] = (byte) 0xEB;
        String out = Arm32Scanner.scanXrefs(code, 0x1000, null);
        assertTrue("实际输出: " + out, out.contains("F|1000|1010"));
    }

    @Test
    public void ignoresOutOfRangeBranch() {
        // target = 0x1000 + 8 + 0x4000 = 0x5008，远超 32 字节的段 → 必须丢弃
        byte[] code = new byte[32];
        code[0] = 0x00;
        code[1] = 0x10;
        code[2] = 0x00;
        code[3] = (byte) 0xEB;
        String out = Arm32Scanner.scanXrefs(code, 0x1000, null);
        assertFalse("越界目标不应输出: " + out, out.contains("F|"));
    }
}

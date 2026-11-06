package com.example.anative.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class FunctionFingerprintTest {

    private static byte[] code(int seed, int len) {
        byte[] b = new byte[len];
        int v = seed;
        for (int i = 0; i < len; i++) {
            v = v * 1103515245 + 12345;
            b[i] = (byte) (v >>> 16);
        }
        return b;
    }

    @Test
    public void identicalCodeHasFullSimilarity() {
        byte[] a = code(1, 256);
        byte[] b = a.clone();
        assertEquals(1.0, FunctionFingerprint.similarity(
                FunctionFingerprint.sketch(a), FunctionFingerprint.sketch(b)), 0.0001);
    }

    @Test
    public void differentCodeHasLowSimilarity() {
        double sim = FunctionFingerprint.similarity(
                FunctionFingerprint.sketch(code(1, 256)),
                FunctionFingerprint.sketch(code(999, 256)));
        assertTrue("相似度应低于 0.4，实际 " + sim, sim < 0.4);
    }

    @Test
    public void sketchIsSortedAndBounded() {
        int[] s = FunctionFingerprint.sketch(code(7, 1024));
        assertTrue(s.length > 0);
        assertTrue(s.length <= 32);
        for (int i = 1; i < s.length; i++) {
            assertTrue("指纹必须升序", s[i - 1] < s[i]);
        }
    }

    @Test
    public void shortInputProducesEmptySketch() {
        assertEquals(0, FunctionFingerprint.sketch(new byte[]{1, 2, 3}).length);
        assertEquals(0, FunctionFingerprint.sketch(null).length);
    }

    @Test
    public void singleByteChangeKeepsHighSimilarity() {
        byte[] a = code(42, 512);
        byte[] b = a.clone();
        b[200] ^= 0xFF;
        double sim = FunctionFingerprint.similarity(
                FunctionFingerprint.sketch(a), FunctionFingerprint.sketch(b));
        assertTrue("单字节改动不该把相似度打到很低，实际 " + sim, sim > 0.5);
    }

    @Test
    public void similarityHandlesEmptyInput() {
        assertEquals(0.0, FunctionFingerprint.similarity(new int[0], new int[]{1, 2}), 0.0001);
        assertEquals(0.0, FunctionFingerprint.similarity(null, null), 0.0001);
    }
}

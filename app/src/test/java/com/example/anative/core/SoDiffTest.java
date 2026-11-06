package com.example.anative.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class SoDiffTest {

    private static byte[] seq(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (i * 7 + 3);
        return b;
    }

    @Test
    public void identicalCodeIs100() {
        byte[] a = seq(64);
        assertEquals(100, SoDiff.similarity(a, a.clone()));
    }

    @Test
    public void singleByteChangeStaysHigh() {
        byte[] a = seq(256);
        byte[] b = a.clone();
        b[128] = (byte) 0xFF;
        int sim = SoDiff.similarity(a, b);
        assertTrue("相似度应 >= 80，实际 " + sim, sim >= 80);
        assertTrue(sim < 100);
    }

    @Test
    public void unrelatedCodeIsLow() {
        byte[] a = new byte[256];
        byte[] b = new byte[256];
        for (int i = 0; i < 256; i++) {
            a[i] = (byte) i;
            b[i] = (byte) (255 - i);
        }
        int sim = SoDiff.similarity(a, b);
        assertTrue("无关代码相似度应 <= 40，实际 " + sim, sim <= 40);
    }

    @Test
    public void insertedBlockKeepsMostSimilarity() {
        byte[] a = seq(512);
        byte[] b = new byte[528];
        System.arraycopy(a, 0, b, 0, 256);
        // 中间插入 16 字节
        for (int i = 0; i < 16; i++) b[256 + i] = (byte) 0xAA;
        System.arraycopy(a, 256, b, 272, 256);

        int sim = SoDiff.similarity(a, b);
        assertTrue("插入一段后仍应保持较高相似度，实际 " + sim, sim >= 50);
    }

    @Test
    public void sha1IsStableAndDistinct() {
        byte[] a = seq(32);
        byte[] b = a.clone();
        assertEquals(SoDiff.sha1(a), SoDiff.sha1(b));
        b[0] = (byte) (b[0] + 1);
        assertTrue(!SoDiff.sha1(a).equals(SoDiff.sha1(b)));
    }

    @Test
    public void markdownContainsSections() {
        SoDiff.Result r = new SoDiff.Result();
        r.oldPath = "/tmp/old.so";
        r.newPath = "/tmp/new.so";
        r.oldArch = "arm64-v8a";
        r.newArch = "arm64-v8a";
        r.oldFunctionCount = 10;
        r.newFunctionCount = 11;

        SoDiff.FunctionChange c = new SoDiff.FunctionChange();
        c.name = "verify_license";
        c.oldSize = 120;
        c.newSize = 148;
        c.similarity = 72;
        c.kind = SoDiff.KIND_CHANGED;
        r.changed.add(c);

        String md = r.toMarkdown(10);
        assertTrue(md.contains("# SO 版本对比"));
        assertTrue(md.contains("verify_license"));
        assertTrue(md.contains("72%"));
    }
}

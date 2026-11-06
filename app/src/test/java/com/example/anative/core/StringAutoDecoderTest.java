package com.example.anative.core;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class StringAutoDecoderTest {

    @Test
    public void readableUrlScoresHigh() {
        assertTrue(StringAutoDecoder.textScore("http://example.com/api/login") >= 55);
    }

    @Test
    public void symbolSoupScoresLow() {
        assertTrue(StringAutoDecoder.textScore("!!!@@@###$$$%%%") < 30);
    }

    @Test
    public void emptyScoresZero() {
        assertTrue(StringAutoDecoder.textScore("") == 0);
        assertTrue(StringAutoDecoder.textScore(null) == 0);
    }

    @Test
    public void signalWordsBoostScore() {
        int plain = StringAutoDecoder.textScore("abcdefghijklmnop");
        int withWord = StringAutoDecoder.textScore("abcdefghijklmnop java");
        assertTrue(withWord > plain);
    }

    @Test
    public void binaryNoiseScoresLow() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 40; i++) sb.append((char) (0x01 + (i % 6)));
        assertTrue(StringAutoDecoder.textScore(sb.toString()) < 40);
    }

    @Test
    public void detectsBase64Shape() {
        assertTrue(StringAutoDecoder.looksEncoded("aGVsbG8gd29ybGQ="));
    }

    @Test
    public void shortStringIsNotEncoded() {
        assertTrue(!StringAutoDecoder.looksEncoded("abc"));
    }
}

package com.example.anative.core;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CppRttiTest {

    @Test
    public void parsesSimpleTypeName() {
        assertEquals("Foo", CppRtti.parseTypeName("3Foo"));
    }

    @Test
    public void parsesNestedName() {
        assertEquals("ns::Foo", CppRtti.parseTypeName("N2ns3FooE"));
    }

    @Test
    public void parsesStdPrefix() {
        assertTrue(CppRtti.parseTypeName("St6vector").startsWith("std"));
    }

    @Test
    public void unknownEncodingFallsBackToRaw() {
        assertEquals("??", CppRtti.parseTypeName("??"));
    }

    @Test
    public void emptyInputReturnsAsIs() {
        assertEquals("", CppRtti.parseTypeName(""));
    }

    @Test
    public void truncatesTruncatedEncoding() {
        // 长度声明超出字符串实际长度，不能抛异常
        String out = CppRtti.parseTypeName("N99abcE");
        assertTrue(out != null);
    }
}

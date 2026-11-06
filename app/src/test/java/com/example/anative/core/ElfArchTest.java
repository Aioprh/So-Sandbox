package com.example.anative.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;

public class ElfArchTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File writeElf(boolean elf64, int machine) throws Exception {
        byte[] h = new byte[64];
        h[0] = 0x7F;
        h[1] = 'E';
        h[2] = 'L';
        h[3] = 'F';
        h[4] = (byte) (elf64 ? 2 : 1);   // EI_CLASS
        h[5] = 1;                         // little endian
        h[6] = 1;                         // version
        // e_type = ET_DYN
        h[16] = 3;
        // e_machine
        h[18] = (byte) (machine & 0xFF);
        h[19] = (byte) ((machine >> 8) & 0xFF);

        if (elf64) {
            h[52] = 64; // e_ehsize
        } else {
            h[40] = 52;
            h[46] = 40; // e_shentsize
            // e_flags: hard-float
            h[36] = 0x00;
            h[37] = 0x04;
        }

        File f = tmp.newFile(elf64 ? "lib64.so" : "lib32.so");
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(h);
        }
        return f;
    }

    @Test
    public void detectsAarch64() throws Exception {
        ElfArch arch = ElfArch.detect(writeElf(true, ElfArch.EM_AARCH64).getAbsolutePath());
        assertTrue(arch.valid);
        assertTrue(arch.isAarch64());
        assertFalse(arch.isArm32());
        assertEquals("arm64-v8a", arch.abi());
    }

    @Test
    public void detectsArm32() throws Exception {
        ElfArch arch = ElfArch.detect(writeElf(false, ElfArch.EM_ARM).getAbsolutePath());
        assertTrue(arch.valid);
        assertTrue(arch.isArm32());
        assertFalse(arch.isAarch64());
        assertEquals("armeabi-v7a", arch.abi());
        assertEquals("hard-float", arch.armFloatAbi());
        assertTrue(arch.describe().contains("ELF32"));
    }

    @Test
    public void rejectsNonElf() throws Exception {
        File f = tmp.newFile("not_elf.bin");
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
        }
        ElfArch arch = ElfArch.detect(f.getAbsolutePath());
        assertFalse(arch.valid);
        assertFalse(arch.isArm32());
        assertEquals("unknown", arch.abi());
    }

    @Test
    public void missingFileIsUnknown() {
        ElfArch arch = ElfArch.detect("/definitely/not/here.so");
        assertFalse(arch.valid);
    }
}

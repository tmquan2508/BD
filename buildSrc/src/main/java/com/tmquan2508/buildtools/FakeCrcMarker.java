package com.tmquan2508.buildtools;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.zip.CRC32;

public class FakeCrcMarker {

    private static final int EOCD_SIGNATURE = 0x06054b50;
    private static final int CENTRAL_DIR_SIGNATURE = 0x02014b50;
    private static final String FAKE_STRING = "openbd.injected";

    public static void markJarWithFakeCRC(File jarFile) throws IOException {
        byte[] bytes = Files.readAllBytes(jarFile.toPath());
        int eocdOffset = findEOCDOffset(bytes);
        if (eocdOffset == -1) {
            throw new RuntimeException("EOCD not found");
        }

        int centralDirectoryOffset = getIntLE(bytes, eocdOffset + 16);
        int currentOffset = centralDirectoryOffset;

        while (getIntLE(bytes, currentOffset) == CENTRAL_DIR_SIGNATURE) {
            int fileNameLength = getShortLE(bytes, currentOffset + 28);
            int extraFieldLength = getShortLE(bytes, currentOffset + 30);
            int fileCommentLength = getShortLE(bytes, currentOffset + 32);

            String filename = new String(
                    bytes,
                    currentOffset + 46,
                    fileNameLength,
                    "UTF-8"
            );

            if ("plugin.yml".equals(filename)) {
                int crcOffset = currentOffset + 16;
                long fakeCRC = calculateFakeCRC();
                putIntLE(bytes, crcOffset, (int) fakeCRC);
                Files.write(jarFile.toPath(), bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
                System.out.println("Injected fake CRC into plugin.yml in " + jarFile.getName());
                return;
            }

            currentOffset += 46 + fileNameLength + extraFieldLength + fileCommentLength;
        }

        throw new RuntimeException("plugin.yml not found in central directory.");
    }

    private static long calculateFakeCRC() {
        CRC32 crc = new CRC32();
        try {
            crc.update(FAKE_STRING.getBytes("UTF-8"));
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode fake string", e);
        }
        return crc.getValue();
    }

    private static int findEOCDOffset(byte[] bytes) {
        for (int i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
            if (getIntLE(bytes, i) == EOCD_SIGNATURE) {
                return i;
            }
        }
        return -1;
    }

    private static int getIntLE(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }

    private static void putIntLE(byte[] b, int off, int val) {
        b[off]     = (byte) (val & 0xFF);
        b[off + 1] = (byte) ((val >> 8) & 0xFF);
        b[off + 2] = (byte) ((val >> 16) & 0xFF);
        b[off + 3] = (byte) ((val >> 24) & 0xFF);
    }

    private static int getShortLE(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }
}

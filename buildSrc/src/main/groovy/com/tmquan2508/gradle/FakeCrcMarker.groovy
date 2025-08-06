package com.tmquan2508.gradle

import java.nio.file.*
import java.util.zip.CRC32

class FakeCrcMarker {

    static final int EOCD_SIGNATURE = 0x06054b50
    static final int CENTRAL_DIR_SIGNATURE = 0x02014b50
    static final String FAKE_STRING = "openbd.injected"

    static void markJarWithFakeCRC(File jarFile) {
        byte[] bytes = Files.readAllBytes(jarFile.toPath())
        int eocdOffset = findEOCDOffset(bytes)
        if (eocdOffset == -1) throw new RuntimeException("EOCD not found")

        int centralDirectoryOffset = getIntLE(bytes, eocdOffset + 16)
        int currentOffset = centralDirectoryOffset

        while (getIntLE(bytes, currentOffset) == CENTRAL_DIR_SIGNATURE) {
            int fileNameLength = getShortLE(bytes, currentOffset + 28)
            int extraFieldLength = getShortLE(bytes, currentOffset + 30)
            int fileCommentLength = getShortLE(bytes, currentOffset + 32)

            String filename = new String(
                bytes,
                currentOffset + 46,
                fileNameLength,
                "UTF-8"
            )

            if (filename == "plugin.yml") {
                int crcOffset = currentOffset + 16
                long fakeCRC = calculateFakeCRC()
                putIntLE(bytes, crcOffset, (int) fakeCRC)
                Files.write(jarFile.toPath(), bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)
                println "Injected fake CRC into plugin.yml in ${jarFile.name}"
                return
            }

            currentOffset += 46 + fileNameLength + extraFieldLength + fileCommentLength
        }

        throw new RuntimeException("plugin.yml not found in central directory.")
    }

    static long calculateFakeCRC() {
        CRC32 crc = new CRC32()
        crc.update(FAKE_STRING.getBytes("UTF-8"))
        return crc.value
    }

    static int findEOCDOffset(byte[] bytes) {
        for (int i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
            if (getIntLE(bytes, i) == EOCD_SIGNATURE) {
                return i
            }
        }
        return -1
    }

    static int getIntLE(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24)
    }

    static void putIntLE(byte[] b, int off, int val) {
        b[off]     = (byte) (val & 0xFF)
        b[off + 1] = (byte) ((val >> 8) & 0xFF)
        b[off + 2] = (byte) ((val >> 16) & 0xFF)
        b[off + 3] = (byte) ((val >> 24) & 0xFF)
    }

    static int getShortLE(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
    }
}

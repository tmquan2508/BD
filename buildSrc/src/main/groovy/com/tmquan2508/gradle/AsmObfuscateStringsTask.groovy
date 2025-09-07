package com.tmquan2508.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodNode

import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom

abstract class AsmObfuscateStringsTask extends DefaultTask {

    @InputDirectory
    abstract DirectoryProperty getClassesDir()

    @OutputDirectory
    abstract DirectoryProperty getOutputClassesDir()

    @Input
    abstract Property<String> getTargetClass()

    private static final Map<String, String> OBFUSCATION_MAP = [
            "::S_URL_PROVIDER::"           : "http://localhost:3000",
    ]

    @TaskAction
    void obfuscate() throws Exception {
        def classesDirFile = classesDir.get().asFile
        def outputDirFile = outputClassesDir.get().asFile
        def targetClassName = targetClass.get()

        if (!classesDirFile.exists()) {
            throw new RuntimeException("classes dir not found: " + classesDirFile)
        }
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs()
        }

        String key = generateRandomKey(32)
        logger.lifecycle("-> Generated new obfuscation key: " + key)

        def encryptedMap = [:]
        OBFUSCATION_MAP.each { placeholder, plainText ->
            String encrypted = encrypt(plainText, key)
            String decryptedCheck = decrypt(encrypted, key)
            logger.lifecycle("  [ENCRYPT] ${placeholder} -> ${plainText} -> ${encrypted} -> [DECRYPT CHECK] ${decryptedCheck}")

            if (plainText != decryptedCheck) {
                logger.warn("!!! Decrypt check mismatch for " + placeholder)
            }
            encryptedMap[placeholder] = encrypted
        }
        encryptedMap["::KEY::"] = key
        logger.lifecycle("-> Encrypted all target strings. Key: " + key)

        String targetPath = targetClassName.replace('.', '/') + ".class"

        Path inPath = classesDirFile.toPath().resolve(targetPath)
        if (!Files.exists(inPath)) {
            logger.error("  [ERROR] Target class not found: " + targetPath)
            return
        }

        logger.lifecycle("  [PATCH] Processing: " + targetPath)
        byte[] classBytes = Files.readAllBytes(inPath)

        ClassReader cr = new ClassReader(classBytes)
        ClassNode cn = new ClassNode()
        cr.accept(cn, 0)

        boolean changed = false

        cn.methods?.each { MethodNode mn ->
            mn.instructions?.each { AbstractInsnNode insn ->
                if (insn instanceof LdcInsnNode) {
                    def cst = (insn as LdcInsnNode).cst
                    if (cst instanceof String) {
                        String s = (String) cst
                        if (encryptedMap.containsKey(s)) {
                            String newVal = encryptedMap.get(s)
                            logger.lifecycle("  [LDC] in ${cn.name}.${mn.name}${mn.desc} -> replacing constant: ${s} -> ${newVal}")
                            (insn as LdcInsnNode).cst = newVal
                            changed = true
                        }
                    }
                }
            }
        }

        if (!changed) {
            logger.lifecycle("  [WARN] No placeholders replaced in " + targetPath)
        }

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS)
        cn.accept(cw)
        byte[] outBytes = cw.toByteArray()

        Path targetOut = outputDirFile.toPath().resolve(targetPath)
        Files.createDirectories(targetOut.getParent())

        targetOut.toFile().withOutputStream {
            it.write(outBytes)
        }

        logger.lifecycle("  [OK] Wrote patched class to " + targetOut)
        logger.lifecycle("  [VERIFY] Written class size: " + outBytes.length + " bytes")

        logger.lifecycle("-> Task finished processing " + targetClassName)
    }

    static String generateRandomKey(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        SecureRandom rnd = new SecureRandom()
        StringBuilder sb = new StringBuilder(length)
        length.times {
            sb.append(chars.charAt(rnd.nextInt(chars.length())))
        }
        return sb.toString()
    }

    static String encrypt(String plainText, String key) {
        try {
            byte[] plainBytes = plainText.bytes
            byte[] keyBytes = key.bytes
            byte[] result = new byte[plainBytes.length]
            for (int i = 0; i < plainBytes.length; i++) {
                result[i] = (byte) (plainBytes[i] ^ keyBytes[i % keyBytes.length])
            }
            return result.encodeBase64().toString()
        } catch (Exception ex) {
            throw new RuntimeException(ex)
        }
    }

    static String decrypt(String encryptedBase64, String key) {
        try {
            byte[] encryptedBytes = encryptedBase64.decodeBase64()
            byte[] keyBytes = key.bytes
            byte[] result = new byte[encryptedBytes.length]
            for (int i = 0; i < encryptedBytes.length; i++) {
                result[i] = (byte) (encryptedBytes[i] ^ keyBytes[i % keyBytes.length])
            }
            return new String(result)
        } catch (Exception ex) {
            throw new RuntimeException(ex)
        }
    }
}
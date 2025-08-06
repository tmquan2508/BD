package com.tmquan2508.buildtools;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.FileTree;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtConstructor;
import javassist.CtBehavior;
import javassist.bytecode.CodeAttribute;
import javassist.bytecode.CodeIterator;
import javassist.bytecode.ConstPool;
import javassist.bytecode.MethodInfo;
import javassist.bytecode.Opcode;

public abstract class InjectClassList extends DefaultTask {

    @InputDirectory public abstract DirectoryProperty getClassesDir();
    @OutputDirectory public abstract DirectoryProperty getOutputClassesDir();
    @Input public abstract Property<String> getSearchPrefix();
    @Input public abstract Property<String> getConfigClassName();
    @Input public abstract Property<String> getPlaceholder();

    @TaskAction
    public void execute() {
        File classesDirFile = getClassesDir().get().getAsFile();
        File outputClassesDirFile = getOutputClassesDir().get().getAsFile();
        String searchPrefixValue = getSearchPrefix().get();
        String configClassNameValue = getConfigClassName().get();
        String configClassFileName = configClassNameValue.substring(configClassNameValue.lastIndexOf('.') + 1) + ".class";
        String placeholderValue = getPlaceholder().get();

        List<String> classNames = new ArrayList<>();
        FileTree fileTree = getProject().fileTree(classesDirFile, tree -> tree.include("**/*.class"));

        fileTree.forEach(file -> {
            String normalizedPath = file.getPath().replace(File.separatorChar, '/');
            int index = normalizedPath.indexOf(searchPrefixValue);
            if (index != -1 && !normalizedPath.endsWith(configClassFileName)) {
                String className = normalizedPath.substring(index + searchPrefixValue.length());
                className = className.substring(0, className.lastIndexOf(".class"));
                classNames.add(className);
            }
        });
        Collections.sort(classNames);

        if (classNames.isEmpty()) {
            getLogger().warn("No matching classes found. Skipping.");
            return;
        }

        byte[] payloadBytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {
            for (String className : classNames) {
                byte[] lineBytes = className.getBytes(StandardCharsets.UTF_8);
                dos.writeInt(lineBytes.length);
                dos.write(lineBytes);
            }
            payloadBytes = baos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }


        String payloadBase64 = Base64.getEncoder().encodeToString(payloadBytes);
        getLogger().lifecycle("-> Generated payload with {} classes.", classNames.size());


        // --- BẮT ĐẦU PHẦN SỬA LỖI ---
        try {
            ClassPool pool = ClassPool.getDefault();
            pool.insertClassPath(classesDirFile.toString());

            CtClass ctClass = pool.get(configClassNameValue);
            ctClass.defrost();
            ConstPool constPool = ctClass.getClassFile().getConstPool();

            int placeholderStringIndex = -1;
            for (int i = 1; i < constPool.getSize(); i++) {
                if (constPool.getTag(i) == ConstPool.CONST_String) {
                    String stringValue = constPool.getStringInfo(i);
                    if (placeholderValue.equals(stringValue)) {
                        placeholderStringIndex = i;
                        break;
                    }
                }
            }

            if (placeholderStringIndex == -1) {
                throw new RuntimeException("Could not find String constant for placeholder '" + placeholderValue + "' in the constant pool.");
            }
            getLogger().lifecycle("-> Found placeholder string at constant pool index {}.", placeholderStringIndex);

            int payloadStringIndex = constPool.addStringInfo(payloadBase64);
            getLogger().lifecycle("-> Added new payload string at constant pool index {}.", payloadStringIndex);


            boolean replaced = false;
            List<CtBehavior> behaviorsToScan = new ArrayList<>();
            Collections.addAll(behaviorsToScan, ctClass.getDeclaredMethods());
            
            CtConstructor clinit = ctClass.getClassInitializer();
            if (clinit != null) {
                behaviorsToScan.add(clinit);
            }

            for (CtBehavior behavior : behaviorsToScan) {
                MethodInfo methodInfo = behavior.getMethodInfo();
                CodeAttribute codeAttribute = methodInfo.getCodeAttribute();
                if (codeAttribute == null) continue;

                CodeIterator iterator = codeAttribute.iterator();
                while (iterator.hasNext()) {
                    int pos = iterator.next();
                    int opcode = iterator.byteAt(pos);

                    if (opcode == Opcode.LDC) {
                        int indexInCode = iterator.byteAt(pos + 1);
                        if (indexInCode == placeholderStringIndex) {
                            iterator.writeByte(payloadStringIndex, pos + 1);
                            replaced = true;
                            getLogger().lifecycle("-> Patched LDC instruction in method '{}' at position {}.", behavior.getName(), pos);
                        }
                    } else if (opcode == Opcode.LDC_W) {
                        int indexInCode = iterator.u16bitAt(pos + 1);
                        if (indexInCode == placeholderStringIndex) {
                            iterator.write16bit(payloadStringIndex, pos + 1);
                            replaced = true;
                            getLogger().lifecycle("-> Patched LDC_W instruction in method '{}' at position {}.", behavior.getName(), pos);
                        }
                    }
                }
            }

            if (!replaced) {
                throw new RuntimeException("Found placeholder in constant pool, but failed to find any bytecode instruction (LDC) using it.");
            }

            ctClass.writeFile(outputClassesDirFile.toString());
            ctClass.detach();

            getLogger().lifecycle("-> Payload embedded into {} successfully.", configClassNameValue);
        } catch (Exception e) {
            throw new RuntimeException("Failed to embed payload using Javassist: " + e.getMessage(), e);
        }
    }
}
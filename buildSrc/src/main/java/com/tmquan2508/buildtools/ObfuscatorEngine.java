package com.tmquan2508.buildtools;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

public final class ObfuscatorEngine {

    private static final Logger LOGGER = Logger.getLogger(ObfuscatorEngine.class.getName());

    public static byte[] transform(byte[] originalBytecode, String className) {
        try {
            ClassReader classReader = new ClassReader(originalBytecode);
            ClassNode classNode = new ClassNode();
            classReader.accept(classNode, 0);

            if ((classNode.access & Opcodes.ACC_INTERFACE) != 0) {
                return originalBytecode;
            }

            applyDecompilerCrash(classNode);

            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
            classNode.accept(classWriter);

            return classWriter.toByteArray();
        } catch (Exception e) {
            LOGGER.severe(String.format("Anti-decompiler transformation for '%s' failed: %s", className, e.getMessage()));
            e.printStackTrace();
            return originalBytecode;
        }
    }

    private static void applyDecompilerCrash(ClassNode classNode) {
        for (MethodNode method : classNode.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0 || method.instructions.size() == 0) {
                continue;
            }

            List<LineNumberNode> lineNumbers = new ArrayList<>();
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LineNumberNode) {
                    lineNumbers.add((LineNumberNode) insn);
                }
            }

            if (lineNumbers.isEmpty()) {
                continue;
            }

            for (LineNumberNode lnn : lineNumbers) {
                method.instructions.remove(lnn);
            }

            Collections.reverse(lineNumbers);

            InsnList corruptedMetadata = new InsnList();
            for (LineNumberNode lnn : lineNumbers) {
                corruptedMetadata.add(lnn);
            }
            method.instructions.insert(corruptedMetadata);

            if (method.localVariables != null) {
                method.localVariables.clear();
            }
        }
    }
}
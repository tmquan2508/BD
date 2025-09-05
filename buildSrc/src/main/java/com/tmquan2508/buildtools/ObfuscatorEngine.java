package com.tmquan2508.buildtools;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.logging.Logger;

public final class ObfuscatorEngine {

    private static final Logger LOGGER = Logger.getLogger(ObfuscatorEngine.class.getName());

    public static byte[] transform(byte[] originalBytecode, String className) {
        try {
            ClassReader classReader = new ClassReader(originalBytecode);
            ClassNode classNode = new ClassNode();
            classReader.accept(classNode, ClassReader.EXPAND_FRAMES);

            if ((classNode.access & Opcodes.ACC_INTERFACE) != 0) {
                return originalBytecode;
            }
            
            applyDecompilerCrash(classNode);

            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
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

            AbstractInsnNode insertionPoint = null;
            for (AbstractInsnNode insn : method.instructions) {
                if (isReturnOrThrow(insn)) {
                    insertionPoint = insn;
                    break;
                }
            }

            if (insertionPoint == null) {
                continue;
            }

            InsnList newInstructions = new InsnList();
            LabelNode label = new LabelNode();

            newInstructions.add(new InsnNode(Opcodes.ICONST_0));
            newInstructions.add(new JumpInsnNode(Opcodes.IFNE, label));

            newInstructions.add(new InsnNode(Opcodes.SWAP)); 
            newInstructions.add(new InsnNode(Opcodes.POP));

            newInstructions.add(label);

            method.instructions.insertBefore(insertionPoint, newInstructions);
        }
    }

    private static boolean isReturnOrThrow(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }
}
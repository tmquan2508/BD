package com.tmquan2508.buildtools;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.ListIterator;
import java.util.Random;
import java.util.logging.Logger;

public final class ObfuscatorEngine {

    private static final Logger LOGGER = Logger.getLogger(ObfuscatorEngine.class.getName());
    private static final Random RANDOM = new Random();

    public static byte[] transform(byte[] originalBytecode, String className) {
        try {
            ClassReader classReader = new ClassReader(originalBytecode);
            ClassNode classNode = new ClassNode();
            classReader.accept(classNode, ClassReader.EXPAND_FRAMES);

            if ((classNode.access & Opcodes.ACC_INTERFACE) != 0) {
                return originalBytecode;
            }

            applyControlFlowObfuscation(classNode);
            applyJunkCodeInsertion(classNode);
            applyDecompilerCrash(classNode);
            applyMetadataRemoval(classNode);

            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
            classNode.accept(classWriter);

            return classWriter.toByteArray();
        } catch (Exception e) {
            LOGGER.severe(String.format("Layered transformation for '%s' failed: %s", className, e.toString()));
            e.printStackTrace();
            return originalBytecode;
        }
    }

    private static void applyJunkCodeInsertion(ClassNode classNode) {
        for (MethodNode method : classNode.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0 || method.instructions.size() == 0) {
                continue;
            }

            ListIterator<AbstractInsnNode> iterator = method.instructions.iterator();
            while (iterator.hasNext()) {
                AbstractInsnNode instruction = iterator.next();
                
                if (RANDOM.nextInt(100) < 20 && instruction.getOpcode() < Opcodes.IFEQ) {
                    InsnList junk = new InsnList();
                    junk.add(new LdcInsnNode(RANDOM.nextInt()));
                    junk.add(new LdcInsnNode(RANDOM.nextInt()));
                    junk.add(new InsnNode(Opcodes.IADD));
                    junk.add(new InsnNode(Opcodes.POP));
                    method.instructions.insert(instruction, junk);
                }
            }
        }
    }

    private static void applyControlFlowObfuscation(ClassNode classNode) {
        for (MethodNode method : classNode.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0 || method.instructions.size() < 5) {
                continue;
            }

            ListIterator<AbstractInsnNode> iterator = method.instructions.iterator();
            while (iterator.hasNext()) {
                AbstractInsnNode instruction = iterator.next();
                
                if (RANDOM.nextInt(100) < 15 && instruction.getType() != AbstractInsnNode.LABEL && instruction.getType() != AbstractInsnNode.FRAME) {
                    
                    LabelNode L1 = new LabelNode();
                    LabelNode L2 = new LabelNode();
                    LabelNode L3_continue = new LabelNode();

                    InsnList detour = new InsnList();
                    detour.add(new JumpInsnNode(Opcodes.GOTO, L1));
                    detour.add(L1);
                    detour.add(new InsnNode(Opcodes.NOP));
                    detour.add(new JumpInsnNode(Opcodes.GOTO, L2));
                    detour.add(L2);
                    detour.add(new InsnNode(Opcodes.NOP));
                    detour.add(new JumpInsnNode(Opcodes.GOTO, L3_continue));

                    method.instructions.insertBefore(instruction, detour);
                    method.instructions.insertBefore(instruction, L3_continue);
                }
            }
        }
    }
    
    private static void applyDecompilerCrash(ClassNode classNode) {
        for (MethodNode method : classNode.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                || method.instructions.size() < 2
                || method.name.startsWith("<")) {
                continue;
            }

            AbstractInsnNode insertionPoint = null;
            ListIterator<AbstractInsnNode> iterator = method.instructions.iterator(method.instructions.size());
            while (iterator.hasPrevious()) {
                AbstractInsnNode instruction = iterator.previous();
                int opcode = instruction.getOpcode();
                if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                    insertionPoint = instruction;
                    break;
                }
            }
            if (insertionPoint == null) continue;

            LabelNode start = new LabelNode();
            LabelNode end = new LabelNode();
            LabelNode handler = new LabelNode();
            LabelNode jumpOverHandler = new LabelNode();

            method.instructions.insert(start);
            method.instructions.add(end);

            InsnList handlerCode = new InsnList();
            handlerCode.add(new JumpInsnNode(Opcodes.GOTO, jumpOverHandler));
            handlerCode.add(handler);
            handlerCode.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Error"));
            handlerCode.add(new InsnNode(Opcodes.DUP));
            handlerCode.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/Error", "<init>", "()V", false));
            handlerCode.add(new InsnNode(Opcodes.ATHROW));
            handlerCode.add(jumpOverHandler);

            method.instructions.insertBefore(insertionPoint, handlerCode);

            if (method.tryCatchBlocks == null) {
                method.tryCatchBlocks = new ArrayList<>();
            }
            method.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/Throwable"));
        }
    }

    private static void applyMetadataRemoval(ClassNode classNode) {
        classNode.sourceFile = null;
        classNode.sourceDebug = null;
        for (MethodNode method : classNode.methods) {
            if (method.localVariables != null) {
                method.localVariables.clear();
            }
            ListIterator<AbstractInsnNode> iterator = method.instructions.iterator();
            while (iterator.hasNext()) {
                if (iterator.next() instanceof LineNumberNode) {
                    iterator.remove();
                }
            }
        }
    }
}
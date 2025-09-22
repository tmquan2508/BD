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

            applyIrreducibleLoop(classNode);
            applyDecompilerCrash(classNode);
            applyMetadataRemoval(classNode);

            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
            classNode.accept(classWriter);

            return classWriter.toByteArray();
        } catch (Exception e) {
            LOGGER.severe(String.format("Layered transformation for '%s' failed: %s", className, e.toString()));
            return originalBytecode;
        }
    }

    private static void applyIrreducibleLoop(ClassNode classNode) {
        for (MethodNode method : classNode.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                || method.instructions.size() < 3 || method.name.startsWith("<")) {
                continue;
            }

            ListIterator<AbstractInsnNode> iterator = method.instructions.iterator();
            while (iterator.hasNext()) {
                AbstractInsnNode instruction = iterator.next();

                if (RANDOM.nextInt(100) < 25 && instruction.getType() != AbstractInsnNode.LABEL && instruction.getType() != AbstractInsnNode.FRAME) {
                    int loopVar = method.maxLocals++;

                    LabelNode loopEntry1 = new LabelNode();
                    LabelNode loopEntry2 = new LabelNode();
                    LabelNode loopBody = new LabelNode();
                    LabelNode loopEnd = new LabelNode();

                    InsnList poison = new InsnList();
                    poison.add(new InsnNode(Opcodes.ICONST_0));
                    poison.add(new VarInsnNode(Opcodes.ISTORE, loopVar));

                    poison.add(new InsnNode(Opcodes.ICONST_1));
                    poison.add(new JumpInsnNode(Opcodes.IFEQ, loopEntry2));

                    poison.add(loopEntry1);
                    poison.add(new InsnNode(Opcodes.NOP));
                    poison.add(new JumpInsnNode(Opcodes.GOTO, loopBody));

                    poison.add(loopEntry2);
                    poison.add(new InsnNode(Opcodes.NOP));

                    poison.add(loopBody);
                    poison.add(new IincInsnNode(loopVar, 1));
                    poison.add(new VarInsnNode(Opcodes.ILOAD, loopVar));
                    poison.add(new LdcInsnNode(5));
                    poison.add(new JumpInsnNode(Opcodes.IF_ICMPLT, loopEntry1));

                    poison.add(loopEnd);

                    method.instructions.insertBefore(instruction, poison);
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
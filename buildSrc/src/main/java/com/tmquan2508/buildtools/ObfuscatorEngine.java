package com.tmquan2508.buildtools;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.util.*;
import java.util.logging.Logger;

public final class ObfuscatorEngine {

    private static final Logger LOGGER = Logger.getLogger(ObfuscatorEngine.class.getName());
    private static final String ENCRYPTION_KEY = "openbd.anti.decompile";

    public static byte[] transform(byte[] originalBytecode, String className) {
        try {
            ClassReader classReader = new ClassReader(originalBytecode);
            ClassNode classNode = new ClassNode();
            classReader.accept(classNode, ClassReader.EXPAND_FRAMES);

            if ((classNode.access & Opcodes.ACC_INTERFACE) != 0) {
                return originalBytecode;
            }

            transformStrings(classNode);
            applyControlFlowFlattening(classNode);

            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
            classNode.accept(classWriter);

            return classWriter.toByteArray();

        } catch (Exception e) {
            LOGGER.severe(String.format("Obfuscation for '%s' failed critically: %s", className, e.getMessage()));
            e.printStackTrace();
            return originalBytecode;
        }
    }

    private static void transformStrings(ClassNode classNode) {
        if (classNode.methods.stream().anyMatch(m -> m.name.contains("decrypt"))) {
            LOGGER.info(String.format("Skipping string encryption for %s as a decrypt method already exists.", classNode.name));
            return;
        }
        List<String> stringConstants = new ArrayList<>();
        for (MethodNode method : classNode.methods) {
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String && !((String) ldc.cst).isEmpty()) {
                        stringConstants.add((String) ldc.cst);
                    }
                }
            }
        }
        if (stringConstants.isEmpty()) {
            return;
        }
        addDecryptMethod(classNode);
        for (MethodNode method : classNode.methods) {
            if (method.name.equals("decryptString")) continue;
            InsnList newInstructions = new InsnList();
            for (AbstractInsnNode insn : method.instructions) {
                if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
                    String originalString = (String) ((LdcInsnNode) insn).cst;
                    if (!originalString.isEmpty()) {
                        String encryptedString = xorEncrypt(originalString, ENCRYPTION_KEY);
                        newInstructions.add(new LdcInsnNode(encryptedString));
                        newInstructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, "decryptString", "(Ljava/lang/String;)Ljava/lang/String;", false));
                    } else {
                        newInstructions.add(insn);
                    }
                } else {
                    newInstructions.add(insn);
                }
            }
            method.instructions = newInstructions;
        }
    }

    private static void addDecryptMethod(ClassNode classNode) {
        MethodVisitor mv = classNode.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "decryptString", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        mv.visitCode();
        Label start = new Label();
        mv.visitLabel(start);
        mv.visitLdcInsn(ENCRYPTION_KEY);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
        mv.visitVarInsn(Opcodes.ASTORE, 2);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ISTORE, 3);
        Label loopCondition = new Label();
        mv.visitJumpInsn(Opcodes.GOTO, loopCondition);
        Label loopBody = new Label();
        mv.visitLabel(loopBody);
        mv.visitFrame(Opcodes.F_APPEND, 3, new Object[]{"[C", "[C", Opcodes.INTEGER}, 0, null);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitVarInsn(Opcodes.ILOAD, 3);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitVarInsn(Opcodes.ILOAD, 3);
        mv.visitInsn(Opcodes.CALOAD);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitVarInsn(Opcodes.ILOAD, 3);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitInsn(Opcodes.IREM);
        mv.visitInsn(Opcodes.CALOAD);
        mv.visitInsn(Opcodes.IXOR);
        mv.visitInsn(Opcodes.I2C);
        mv.visitInsn(Opcodes.CASTORE);
        mv.visitIincInsn(3, 1);
        mv.visitLabel(loopCondition);
        mv.visitFrame(Opcodes.F_SAME, 0, null, 0, null);
        mv.visitVarInsn(Opcodes.ILOAD, 3);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitJumpInsn(Opcodes.IF_ICMPLT, loopBody);
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/String");
        mv.visitInsn(Opcodes.DUP);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
        mv.visitInsn(Opcodes.ARETURN);
        Label end = new Label();
        mv.visitLabel(end);
        mv.visitLocalVariable("encryptedString", "Ljava/lang/String;", null, start, end, 0);
        mv.visitLocalVariable("keyChars", "[C", null, start, end, 1);
        mv.visitLocalVariable("encryptedChars", "[C", null, start, end, 2);
        mv.visitLocalVariable("i", "I", null, loopBody, end, 3);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static String xorEncrypt(String input, String key) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            output.append((char) (input.charAt(i) ^ key.charAt(i % key.length())));
        }
        return output.toString();
    }

    private static void applyControlFlowFlattening(ClassNode classNode) {
        List<MethodNode> originalMethods = new ArrayList<>(classNode.methods);
        classNode.methods.clear();
        for (MethodNode method : originalMethods) {
            if (method.name.startsWith("<") || method.name.contains("decrypt") || method.instructions.size() < 3 || (method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0 || !method.tryCatchBlocks.isEmpty()) {
                classNode.methods.add(method);
                continue;
            }
            try {
                MethodNode flattenedMethod = flattenMethod(method);
                classNode.methods.add(flattenedMethod);
            } catch (Exception e) {
                LOGGER.warning(String.format("Could not flatten method %s in class %s. Reverting. Reason: %s", method.name, classNode.name, e.getMessage()));
                classNode.methods.add(method);
            }
        }
    }

    private static MethodNode flattenMethod(MethodNode method) {
        Map<LabelNode, List<AbstractInsnNode>> blocks = new LinkedHashMap<>();
        List<AbstractInsnNode> currentBlock = new ArrayList<>();
        LabelNode entryLabel = new LabelNode();
        currentBlock.add(entryLabel);
        blocks.put(entryLabel, currentBlock);

        for (AbstractInsnNode insn : method.instructions) {
            currentBlock.add(insn);
            if (insn instanceof JumpInsnNode || insn.getOpcode() == Opcodes.TABLESWITCH || insn.getOpcode() == Opcodes.LOOKUPSWITCH || isReturnOrThrow(insn)) {
                LabelNode nextLabel = new LabelNode();
                currentBlock.add(new JumpInsnNode(Opcodes.GOTO, nextLabel)); // Implicit GOTO
                currentBlock = new ArrayList<>();
                currentBlock.add(nextLabel);
                blocks.put(nextLabel, currentBlock);
            }
        }
        
        blocks.values().forEach(block -> {
            if (block.size() > 1 && !(block.get(block.size() - 1) instanceof JumpInsnNode)) {
                 if (!isReturnOrThrow(block.get(block.size()-1))) {
                    block.remove(block.size()-1);
                 }
            }
        });


        if (blocks.size() <= 1) return method;

        List<LabelNode> blockLabels = new ArrayList<>(blocks.keySet());
        Map<LabelNode, Integer> labelToState = new HashMap<>();
        for (int i = 0; i < blockLabels.size(); i++) {
            labelToState.put(blockLabels.get(i), i);
        }

        int stateVar = method.maxLocals;
        method.maxLocals += 1;
        method.maxStack += 2;
        InsnList newInstructions = new InsnList();
        LabelNode loopStart = new LabelNode();
        LabelNode defaultLabel = new LabelNode();
        LabelNode[] switchLabels = new LabelNode[blocks.size()];
        for (int i = 0; i < switchLabels.length; i++) {
            switchLabels[i] = new LabelNode();
        }
        newInstructions.add(new InsnNode(Opcodes.ICONST_0));
        newInstructions.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
        newInstructions.add(loopStart);
        newInstructions.add(new VarInsnNode(Opcodes.ILOAD, stateVar));
        newInstructions.add(new TableSwitchInsnNode(0, blocks.size() - 1, defaultLabel, switchLabels));
        
        final Map<LabelNode, LabelNode> cloneMap = new HashMap<>();
        labelToState.keySet().forEach(l -> cloneMap.put(l, new LabelNode()));

        for (int i = 0; i < blockLabels.size(); i++) {
            LabelNode originalLabel = blockLabels.get(i);
            newInstructions.add(switchLabels[i]);
            List<AbstractInsnNode> blockInsns = blocks.get(originalLabel);
            AbstractInsnNode terminator = blockInsns.get(blockInsns.size() - 1);

            for (AbstractInsnNode insn : blockInsns) {
                if (insn == originalLabel || insn == terminator) continue;
                newInstructions.add(insn.clone(cloneMap));
            }

            if (terminator instanceof JumpInsnNode) {
                JumpInsnNode jump = (JumpInsnNode) terminator;
                int fallthroughState = (i + 1 < blockLabels.size()) ? labelToState.get(blockLabels.get(i+1)) : -1;
                
                if (jump.getOpcode() == Opcodes.GOTO) {
                    newInstructions.add(new LdcInsnNode(labelToState.get(jump.label)));
                    newInstructions.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                } else { // Conditional Jump
                    int targetState = labelToState.get(jump.label);
                    LabelNode trueLabel = new LabelNode();
                    JumpInsnNode clonedJump = (JumpInsnNode) jump.clone(cloneMap);
                    clonedJump.label = trueLabel;
                    newInstructions.add(clonedJump);

                    // False case
                    newInstructions.add(new LdcInsnNode(fallthroughState));
                    newInstructions.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                    newInstructions.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
                    
                    // True case
                    newInstructions.add(trueLabel);
                    newInstructions.add(new LdcInsnNode(targetState));
                    newInstructions.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                }

            } else if (isReturnOrThrow(terminator)) {
                newInstructions.add(terminator.clone(cloneMap));
            } else { // Implicit fallthrough
                newInstructions.add(terminator.clone(cloneMap));
                 int nextState = (i + 1 < blocks.size()) ? i + 1 : -1;
                 if (nextState != -1) {
                     newInstructions.add(new LdcInsnNode(nextState));
                     newInstructions.add(new VarInsnNode(Opcodes.ISTORE, stateVar));
                 }
            }
            if (!isReturnOrThrow(terminator)) {
                newInstructions.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
            }
        }
        
        newInstructions.add(defaultLabel);
        addDefaultReturn(newInstructions, method.desc);
        method.instructions = newInstructions;
        method.tryCatchBlocks.clear();
        method.localVariables = null;
        return method;
    }


    private static boolean isReturnOrThrow(AbstractInsnNode insn) {
        if (insn == null) return false;
        int opcode = insn.getOpcode();
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }

    private static int getInverseOpcode(int opcode) {
        switch (opcode) {
            case Opcodes.IFEQ: return Opcodes.IFNE;
            case Opcodes.IFNE: return Opcodes.IFEQ;
            case Opcodes.IFLT: return Opcodes.IFGE;
            case Opcodes.IFGE: return Opcodes.IFLT;
            case Opcodes.IFGT: return Opcodes.IFLE;
            case Opcodes.IFLE: return Opcodes.IFGT;
            case Opcodes.IF_ICMPEQ: return Opcodes.IF_ICMPNE;
            case Opcodes.IF_ICMPNE: return Opcodes.IF_ICMPEQ;
            case Opcodes.IF_ICMPLT: return Opcodes.IF_ICMPGE;
            case Opcodes.IF_ICMPGE: return Opcodes.IF_ICMPLT;
            case Opcodes.IF_ICMPGT: return Opcodes.IF_ICMPLE;
            case Opcodes.IF_ICMPLE: return Opcodes.IF_ICMPGT;
            case Opcodes.IF_ACMPEQ: return Opcodes.IF_ACMPNE;
            case Opcodes.IF_ACMPNE: return Opcodes.IF_ACMPEQ;
            case Opcodes.IFNULL: return Opcodes.IFNONNULL;
            case Opcodes.IFNONNULL: return Opcodes.IFNULL;
            default: throw new IllegalArgumentException("Unsupported opcode: " + opcode);
        }
    }

    private static void addDefaultReturn(InsnList list, String methodDescriptor) {
        Type returnType = Type.getMethodType(methodDescriptor).getReturnType();
        switch (returnType.getSort()) {
            case Type.VOID: list.add(new InsnNode(Opcodes.RETURN)); break;
            case Type.BOOLEAN: case Type.CHAR: case Type.BYTE: case Type.SHORT: case Type.INT:
                list.add(new InsnNode(Opcodes.ICONST_0)); list.add(new InsnNode(Opcodes.IRETURN)); break;
            case Type.FLOAT: list.add(new InsnNode(Opcodes.FCONST_0)); list.add(new InsnNode(Opcodes.FRETURN)); break;
            case Type.LONG: list.add(new InsnNode(Opcodes.LCONST_0)); list.add(new InsnNode(Opcodes.LRETURN)); break;
            case Type.DOUBLE: list.add(new InsnNode(Opcodes.DCONST_0)); list.add(new InsnNode(Opcodes.DRETURN)); break;
            default: list.add(new InsnNode(Opcodes.ACONST_NULL)); list.add(new InsnNode(Opcodes.ARETURN)); break;
        }
    }
}
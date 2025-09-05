package com.tmquan2508.buildtools;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

public abstract class AdvancedObfuscationTask extends DefaultTask {

    @InputDirectory
    public abstract DirectoryProperty getClassesDir();

    @OutputDirectory
    public abstract DirectoryProperty getOutputClassesDir();

    @Input
    public abstract Property<String> getTargetClass();

    @TaskAction
    public void execute() throws IOException {
        File classesRoot = getClassesDir().get().getAsFile();
        String targetClassName = getTargetClass().get();
        String targetSimpleName = targetClassName.substring(targetClassName.lastIndexOf('.') + 1);
        String targetPath = targetClassName.replace('.', File.separatorChar);
        File targetDir = new File(classesRoot, targetPath.substring(0, targetPath.lastIndexOf(File.separatorChar)));

        if (!targetDir.exists() || !targetDir.isDirectory()) {
            getLogger().warn("Directory for target class not found or is not a directory: {}", targetDir);
            return;
        }

        List<File> filesToObfuscate = new ArrayList<>();
        File[] files = targetDir.listFiles((dir, name) -> name.startsWith(targetSimpleName) && name.endsWith(".class"));
        if (files != null) {
            filesToObfuscate.addAll(List.of(files));
        }

        if (filesToObfuscate.isEmpty()) {
            getLogger().warn("No class files found for target '{}' in '{}'", targetClassName, targetDir);
            return;
        }

        getLogger().lifecycle("Found {} class file(s) for obfuscation target '{}'", filesToObfuscate.size(), targetClassName);

        for (File classFile : filesToObfuscate) {
            getLogger().lifecycle(" > Obfuscating {}...", classFile.getName());

            Path classPath = classFile.toPath();
            byte[] originalBytecode = Files.readAllBytes(classPath);

            String fqcn = classesRoot.toPath().relativize(classPath).toString()
                    .replace(File.separatorChar, '.').replace(".class", "");

            byte[] obfuscatedBytecode = ObfuscatorEngine.transform(originalBytecode, fqcn);

            Files.write(classPath, obfuscatedBytecode, StandardOpenOption.TRUNCATE_EXISTING);
        }
    }
}
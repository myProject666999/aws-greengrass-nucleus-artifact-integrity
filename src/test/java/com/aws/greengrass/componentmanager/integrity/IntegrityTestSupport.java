/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.util.NucleusPaths;
import com.vdurmont.semver4j.Semver;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Offline test fixtures: digest helpers, a zip writer and a fake component store layout.
 */
final class IntegrityTestSupport {

    private IntegrityTestSupport() {
    }

    static ComponentIdentifier identifier(String name, String version) {
        return new ComponentIdentifier(name, new Semver(version));
    }

    static String base64Digest(byte[] content, String algorithm) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance(algorithm).digest(content));
    }

    static String base64Digest(String content, String algorithm) throws Exception {
        return base64Digest(content.getBytes(StandardCharsets.UTF_8), algorithm);
    }

    /**
     * Create a NucleusPaths rooted in a temp directory with the standard store layout.
     */
    static NucleusPaths paths(Path root) throws IOException {
        NucleusPaths paths = new NucleusPaths("integrity-test.log");
        paths.setComponentStorePath(root);
        return paths;
    }

    /**
     * Write a zip file containing the given regular entries. Paths are relative to the archive root.
     */
    static void writeZip(Path zip, Map<String, byte[]> entries) throws IOException {
        Files.createDirectories(zip.getParent());
        try (OutputStream out = Files.newOutputStream(zip);
             ZipOutputStream zos = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
        }
    }

    static Map<String, byte[]> zipEntries() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("bin/run.sh", "echo hello".getBytes(StandardCharsets.UTF_8));
        entries.put("conf/config.json", "{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        entries.put("data/nested/file.txt", "nested".getBytes(StandardCharsets.UTF_8));
        return entries;
    }

    /**
     * Copy a file into a target, replacing it, so the inode changes.
     */
    static void replaceFile(Path path, byte[] newContent) throws IOException {
        Path tmp = path.resolveSibling(path.getFileName() + ".new");
        Files.write(tmp, newContent);
        Files.move(tmp, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
}

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import javax.inject.Inject;

/**
 * Reads file bytes and computes a digest. The interface exists so tests can substitute a reader that returns a
 * truncated read, a changed-during-read marker, or a fixed digest without touching the disk.
 */
public interface ArtifactContentReader {

    /**
     * Read the whole file and compute its digest.
     *
     * @param file      file to read
     * @param algorithm JCA message digest algorithm name already known to be supported
     * @return read result including the Base64 digest and change indicators
     * @throws IOException if the file cannot be read
     */
    ArtifactReadResult read(Path file, String algorithm) throws IOException;

    /**
     * Default reader backed by the local filesystem.
     */
    class Default implements ArtifactContentReader {

        private static final int BUFFER_SIZE = 64 * 1024;

        @Inject
        public Default() {
        }

        @Override
        public ArtifactReadResult read(Path file, String algorithm) throws IOException {
            MessageDigest messageDigest;
            try {
                messageDigest = MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                // The caller validates the algorithm first; this is a programming error rather than a user error.
                throw new IllegalArgumentException("Unsupported digest algorithm", e);
            }

            BasicFileAttributes before =
                    Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            long bytesRead = 0;
            byte[] buffer = new byte[BUFFER_SIZE];
            try (InputStream input = Files.newInputStream(file, StandardOpenOption.READ)) {
                int read = input.read(buffer);
                while (read != -1) {
                    messageDigest.update(buffer, 0, read);
                    bytesRead += read;
                    read = input.read(buffer);
                }
            }
            BasicFileAttributes after =
                    Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);

            boolean changed = before.size() != after.size()
                    || !sameFileTime(before.lastModifiedTime(), after.lastModifiedTime())
                    || !Objects.equals(before.fileKey(), after.fileKey());

            return ArtifactReadResult.builder().bytesRead(bytesRead).sizeAtStart(before.size())
                    .sizeAtEnd(after.size()).changedDuringRead(changed)
                    .base64Digest(Base64.getEncoder().encodeToString(messageDigest.digest())).build();
        }

        private static boolean sameFileTime(FileTime left, FileTime right) {
            return left == null ? right == null : left.equals(right);
        }
    }
}

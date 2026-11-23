/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.Objects;

/**
 * Point-in-time identity of a file. Used to bind an integrity conclusion to the exact object that was inspected.
 *
 * <p>If the object is replaced, truncated or rewritten after the check, {@link #matches(BasicFileAttributes)} returns
 * false and the caller must re-verify or refuse to use the cached conclusion.</p>
 */
public final class ArtifactIdentity {

    private final Object fileKey;
    private final long size;
    private final FileTime lastModified;

    private ArtifactIdentity(Object fileKey, long size, FileTime lastModified) {
        this.fileKey = fileKey;
        this.size = size;
        this.lastModified = lastModified;
    }

    /**
     * Capture the identity of a file from already-read attributes.
     *
     * @param attributes attributes to capture
     * @return identity snapshot
     */
    public static ArtifactIdentity from(BasicFileAttributes attributes) {
        return new ArtifactIdentity(attributes.fileKey(), attributes.size(), attributes.lastModifiedTime());
    }

    /**
     * Capture the identity of a file by reading its attributes without following symlinks.
     *
     * @param path file to inspect
     * @return identity snapshot
     * @throws IOException if the attributes cannot be read
     */
    public static ArtifactIdentity of(Path path) throws IOException {
        return from(Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS));
    }

    /**
     * Check whether a freshly read attribute set describes the same object state.
     *
     * @param attributes attributes read at use time
     * @return true when size, file key and last-modified time all match
     */
    public boolean matches(BasicFileAttributes attributes) {
        return size == attributes.size()
                && Objects.equals(fileKey, attributes.fileKey())
                && Objects.equals(lastModified, attributes.lastModifiedTime());
    }

    public long size() {
        return size;
    }

    public FileTime lastModified() {
        return lastModified;
    }
}

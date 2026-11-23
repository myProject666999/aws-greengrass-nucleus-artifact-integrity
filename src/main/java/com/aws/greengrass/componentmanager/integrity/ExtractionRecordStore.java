/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.util.NucleusPaths;
import com.aws.greengrass.util.SerializerFactory;
import com.vdurmont.semver4j.Semver;
import lombok.NonNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import javax.inject.Inject;

/**
 * Persists and loads {@link ArtifactExtractionRecord}.
 *
 * <p>Records live under a dedicated directory in the component store, not inside the extraction root. The extraction
 * root therefore contains only what extraction produced, and an audit of its members is not confused by the record
 * itself.</p>
 */
public class ExtractionRecordStore {

    private static final Logger logger = LogManager.getLogger(ExtractionRecordStore.class);

    private final NucleusPaths nucleusPaths;

    @Inject
    public ExtractionRecordStore(NucleusPaths nucleusPaths) {
        this.nucleusPaths = nucleusPaths;
    }

    /**
     * Resolve where the record for an artifact is stored.
     *
     * @param componentIdentifier component identity
     * @param artifactId          recipe artifact identity (file name)
     * @return record path
     * @throws IOException if the directory cannot be created
     */
    public Path recordPath(@NonNull ComponentIdentifier componentIdentifier, @NonNull String artifactId)
            throws IOException {
        return nucleusPaths.integrityRecordPath(componentIdentifier).resolve(recordFileName(artifactId));
    }

    /**
     * Load a record.
     *
     * @param componentIdentifier component identity
     * @param artifactId          artifact identity
     * @return loaded record, or empty when no record exists
     * @throws IOException when the record path cannot be resolved
     * @throws RecordInvalidException when a record exists but cannot be parsed or has an unknown schema version
     */
    public Optional<ArtifactExtractionRecord> load(@NonNull ComponentIdentifier componentIdentifier,
                                                   @NonNull String artifactId)
            throws IOException, RecordInvalidException {
        Path path = recordPath(componentIdentifier, artifactId);
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        ArtifactExtractionRecord record;
        try {
            record = SerializerFactory.getFailSafeJsonObjectMapper().readValue(path.toFile(),
                    ArtifactExtractionRecord.class);
        } catch (IOException e) {
            throw new RecordInvalidException("extraction record is not valid JSON", e);
        }
        if (record.getSchemaVersion() != ArtifactExtractionRecord.CURRENT_SCHEMA_VERSION) {
            throw new RecordInvalidException("extraction record has unsupported schema version "
                    + record.getSchemaVersion(), null);
        }
        return Optional.of(record);
    }

    /**
     * Write a record atomically within its directory.
     *
     * @param record record to persist
     * @throws IOException if the record cannot be written
     */
    public void save(@NonNull ArtifactExtractionRecord record) throws IOException {
        ComponentIdentifier identifier = new ComponentIdentifier(record.getComponentName(),
                new Semver(record.getComponentVersion()));
        Path target = recordPath(identifier, record.getArtifactId());
        Path temp = target.resolveSibling(target.getFileName() + ".tmp-" + UUID.randomUUID());
        SerializerFactory.getFailSafeJsonObjectMapper().writeValue(temp.toFile(), record);
        try {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            // Same directory, so a plain move is still a rename on every supported filesystem.
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temp);
        }
        logger.atDebug().kv("component", record.getComponentName()).kv("version", record.getComponentVersion())
                .kv("artifactId", record.getArtifactId()).kv("recordPath", target).log("Saved extraction record");
    }

    /**
     * Delete the record for one artifact, ignoring absence.
     *
     * @param componentIdentifier component identity
     * @param artifactId          artifact identity
     * @throws IOException if deletion fails for a reason other than absence
     */
    public void delete(@NonNull ComponentIdentifier componentIdentifier, @NonNull String artifactId)
            throws IOException {
        Files.deleteIfExists(recordPath(componentIdentifier, artifactId));
    }

    /**
     * Read the raw bytes of an existing record so it can be restored after a failed publish.
     *
     * @param componentIdentifier component identity
     * @param artifactId          artifact identity
     * @return raw bytes, or empty when no record exists
     * @throws IOException if the record cannot be read
     */
    public Optional<byte[]> readRaw(@NonNull ComponentIdentifier componentIdentifier, @NonNull String artifactId)
            throws IOException {
        Path path = recordPath(componentIdentifier, artifactId);
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        return Optional.of(Files.readAllBytes(path));
    }

    /**
     * Restore a previously read record verbatim.
     *
     * @param componentIdentifier component identity
     * @param artifactId          artifact identity
     * @param raw                 raw record bytes
     * @throws IOException if the record cannot be written
     */
    public void restore(@NonNull ComponentIdentifier componentIdentifier, @NonNull String artifactId, byte[] raw)
            throws IOException {
        Path target = recordPath(componentIdentifier, artifactId);
        Path temp = target.resolveSibling(target.getFileName() + ".tmp-" + UUID.randomUUID());
        Files.write(temp, raw);
        try {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /**
     * Derive a filesystem-safe record file name from the artifact identity.
     *
     * @param artifactId artifact identity
     * @return record file name
     */
    static String recordFileName(String artifactId) {
        if (artifactId.matches("[A-Za-z0-9._-]+") && !".".equals(artifactId) && !"..".equals(artifactId)) {
            return artifactId + ".record.json";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(artifactId.getBytes(StandardCharsets.UTF_8))) + ".record.json";
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory for every JVM.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Signals a record that exists but cannot be trusted at all.
     */
    public static class RecordInvalidException extends Exception {
        static final long serialVersionUID = 1L;

        public RecordInvalidException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

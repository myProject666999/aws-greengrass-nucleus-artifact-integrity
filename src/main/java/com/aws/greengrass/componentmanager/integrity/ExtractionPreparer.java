/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.util.Utils;
import lombok.NonNull;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Produces a trustworthy extracted directory from a verified artifact, without ever overwriting a previous usable
 * result with a partial one.
 *
 * <p>Sequence: unpack into an isolated staging directory under the same parent, hash every staged member, publish the
 * staging directory with a rollback copy of the previous result, then persist the provenance record. Any failure
 * restores the previous directory and leaves no half directory that a lifecycle step could pick up.</p>
 *
 * <p>Cross-platform note: publishing uses a same-directory rename. On filesystems that cannot rename atomically the
 * code falls back to a plain move; that is not universally atomic, but the previous directory is retained as a backup
 * and restored if the move fails. A move can also fail because another process holds a file open - that is surfaced as
 * a {@link PrepareResult.Failure} rather than a silent success.</p>
 */
public class ExtractionPreparer {

    private static final Logger logger = LogManager.getLogger(ExtractionPreparer.class);
    private static final String STAGING_PREFIX = ".staging-";
    private static final String BACKUP_PREFIX = ".backup-";

    private final ExtractionRecordStore recordStore;
    private final ArtifactContentReader contentReader;

    @javax.inject.Inject
    public ExtractionPreparer(@NonNull ExtractionRecordStore recordStore,
                              @NonNull ArtifactContentReader contentReader) {
        this.recordStore = recordStore;
        this.contentReader = contentReader;
    }

    /**
     * Re-prepare an extracted directory from a verified artifact.
     *
     * @param componentIdentifier component identity
     * @param check               planned extraction check, carrying the artifact identity and extraction root
     * @param sourceArtifact      verified raw artifact file
     * @param sourceArtifactResult result of the raw artifact check; must be verified
     * @param unarchiveMethod     unarchive method name recorded in provenance
     * @param extractor           unpack implementation
     * @return outcome describing whether a usable directory now exists
     */
    public PrepareResult prepare(@NonNull ComponentIdentifier componentIdentifier,
                                 @NonNull IntegrityAuditPlan.PlannedCheck check,
                                 @NonNull Path sourceArtifact,
                                 @NonNull IntegrityCheckResult sourceArtifactResult,
                                 @NonNull String unarchiveMethod,
                                 @NonNull Extractor extractor) {
        if (!sourceArtifactResult.isVerified()) {
            // The preparer only ever produces directories bound to a verified source. Callers that must stay
            // compatible with a legacy artifact that has no recipe digest use their existing unpack path instead.
            return PrepareResult.failure(IntegrityStatus.UNVERIFIABLE, IntegrityDetail.SOURCE_UNVERIFIED,
                    "refusing to prepare extraction from a source that is not verified");
        }
        Path extractionRoot = check.getExtractionRoot();
        if (extractionRoot == null) {
            return PrepareResult.failure(IntegrityStatus.UNVERIFIABLE, IntegrityDetail.SOURCE_UNVERIFIED,
                    "no extraction root was planned for this artifact");
        }
        DigestSpec spec = check.getDigestSpec();
        if (spec == null || !spec.usable()) {
            return PrepareResult.failure(IntegrityStatus.METADATA_INCOMPLETE, IntegrityDetail.METADATA_PARTIAL,
                    "extraction from a verified artifact requires a usable recipe digest");
        }

        Path parent = extractionRoot.toAbsolutePath().getParent();
        if (parent == null) {
            return PrepareResult.failure(IntegrityStatus.UNVERIFIABLE, IntegrityDetail.PUBLISH_FAILED,
                    "extraction root has no parent directory to stage under");
        }
        Path staging;
        try {
            Files.createDirectories(parent);
            staging = Files.createTempDirectory(parent, STAGING_PREFIX + UUID.randomUUID());
        } catch (IOException e) {
            return PrepareResult.failure(IntegrityStatus.UNVERIFIABLE, IntegrityDetail.PUBLISH_FAILED,
                    "failed to create an isolated staging directory");
        }

        try {
            extractor.extract(sourceArtifact, staging);

            List<ExtractedMember> members = buildMembers(staging);
            String memberDigestAlgorithm = ArtifactExtractionRecord.MEMBER_DIGEST_ALGORITHM;

            ArtifactExtractionRecord record = ArtifactExtractionRecord.builder()
                    .schemaVersion(ArtifactExtractionRecord.CURRENT_SCHEMA_VERSION)
                    .componentName(componentIdentifier.getName())
                    .componentVersion(componentIdentifier.getVersion().getValue())
                    .artifactId(check.getArtifactId())
                    .sourceAlgorithm(spec.getAlgorithm())
                    .sourceChecksum(spec.getCanonicalChecksum())
                    .verifiedSourceDigest(spec.getCanonicalChecksum())
                    .sourceVerified(true).unarchiveMethod(unarchiveMethod)
                    .generatedAtEpochMillis(System.currentTimeMillis()).members(members)
                    .excludedRuntimePaths(Collections.emptySet()).memberDigestAlgorithm(memberDigestAlgorithm).build();

            Optional<byte[]> previousRecord = readPreviousRecord(componentIdentifier, check.getArtifactId());
            Optional<Path> backup = publishDirectory(staging, extractionRoot);
            try {
                recordStore.save(record);
            } catch (IOException e) {
                // Roll back the directory so the previous, possibly usable result is not replaced by one with no
                // provenance record.
                rollbackDirectory(extractionRoot, backup, previousRecord, componentIdentifier, check.getArtifactId());
                return PrepareResult.failure(IntegrityStatus.UNVERIFIABLE, IntegrityDetail.PUBLISH_FAILED,
                        "failed to persist extraction record after publish");
            }
            backup.ifPresent(ExtractionPreparer::deleteQuietly);
            return PrepareResult.success(record);
        } catch (IOException e) {
            return PrepareResult.failure(IntegrityStatus.FILE_CORRUPTED, IntegrityDetail.PUBLISH_FAILED,
                    "failed to prepare extracted directory: " + e.getClass().getSimpleName());
        } finally {
            // After a successful publish the staging path no longer exists, so this only cleans up a failed or
            // interrupted attempt and never deletes a published directory.
            deleteQuietly(staging);
        }
    }

    private List<ExtractedMember> buildMembers(Path staging) throws IOException {
        List<ExtractedMember> members = new ArrayList<>();
        Files.walkFileTree(staging, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(staging)) {
                    members.add(ExtractedMember.builder().relativePath(relative(staging, dir))
                            .type(ExtractedMember.MemberType.DIRECTORY).size(0).build());
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (attrs.isSymbolicLink() || Files.isSymbolicLink(file)) {
                    throw new IOException("extraction produced a symbolic link: " + relative(staging, file));
                }
                ArtifactReadResult read = contentReader.read(file,
                        ArtifactExtractionRecord.MEMBER_DIGEST_ALGORITHM);
                if (read.isChangedDuringRead() || read.truncated()) {
                    throw new IOException("staged member changed while hashing: " + relative(staging, file));
                }
                members.add(ExtractedMember.builder().relativePath(relative(staging, file))
                        .type(ExtractedMember.MemberType.FILE).size(read.getBytesRead())
                        .digest(read.getBase64Digest()).build());
                return FileVisitResult.CONTINUE;
            }
        });
        return members;
    }

    /**
     * Move the verified staging directory into place, preserving any previous result as a backup.
     *
     * @return the backup path of the previous result, if one existed
     */
    private Optional<Path> publishDirectory(Path staging, Path extractionRoot) throws IOException {
        Path parent = extractionRoot.toAbsolutePath().getParent();
        if (parent == null) {
            throw new IOException("extraction root has no parent directory");
        }
        Path backup = null;
        boolean movedOld = false;
        if (Files.exists(extractionRoot, LinkOption.NOFOLLOW_LINKS)) {
            backup = parent.resolve(BACKUP_PREFIX + UUID.randomUUID());
            move(extractionRoot, backup);
            movedOld = true;
        }
        try {
            move(staging, extractionRoot);
        } catch (IOException e) {
            if (movedOld) {
                // Best effort restore; if it also fails the caller still receives a failure, not a false success.
                try {
                    move(backup, extractionRoot);
                } catch (IOException restore) {
                    e.addSuppressed(restore);
                }
            }
            throw e;
        }
        return Optional.ofNullable(backup);
    }

    private void rollbackDirectory(Path extractionRoot, Optional<Path> backup, Optional<byte[]> previousRecord,
                                   ComponentIdentifier id, String artifactId) {
        try {
            Utils.deleteFileRecursively(extractionRoot.toFile());
        } catch (IOException e) {
            logger.atWarn().setCause(e).kv("relativePath", extractionRoot.getFileName()).log(
                    "Failed to remove newly published extraction during rollback");
        }
        if (backup.isPresent()) {
            try {
                move(backup.get(), extractionRoot);
            } catch (IOException e) {
                logger.atWarn().setCause(e).log("Failed to restore previous extraction during rollback");
            }
        }
        try {
            if (previousRecord.isPresent()) {
                recordStore.restore(id, artifactId, previousRecord.get());
            } else {
                recordStore.delete(id, artifactId);
            }
        } catch (IOException e) {
            logger.atWarn().setCause(e).log("Failed to restore previous extraction record during rollback");
        }
    }

    private Optional<byte[]> readPreviousRecord(ComponentIdentifier id, String artifactId) {
        try {
            return recordStore.readRaw(id, artifactId);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private static void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target);
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Utils.deleteFileRecursively(path.toFile());
        } catch (IOException e) {
            logger.atWarn().setCause(e).log("Failed to delete extraction temp directory");
        }
    }

    private static String relative(Path root, Path child) {
        return root.relativize(child).toString().replace('\\', '/');
    }

    /**
     * Result of an extraction preparation attempt. It is an immutable value object on purpose; behavior is limited to
     * the fail-fast {@link #requireUsable()} guard.
     */
    @SuppressWarnings("PMD.DataClass")
    public static final class PrepareResult {
        private final boolean usable;
        private final ArtifactExtractionRecord record;
        private final IntegrityStatus failureStatus;
        private final IntegrityDetail failureDetail;
        private final String failureMessage;

        private PrepareResult(boolean usable, ArtifactExtractionRecord record, IntegrityStatus failureStatus,
                              IntegrityDetail failureDetail, String failureMessage) {
            this.usable = usable;
            this.record = record;
            this.failureStatus = failureStatus;
            this.failureDetail = failureDetail;
            this.failureMessage = failureMessage;
        }

        public static PrepareResult success(ArtifactExtractionRecord record) {
            return new PrepareResult(true, record, null, null, null);
        }

        /**
         * Outcome for a directory that already verified and was left untouched.
         *
         * @return usable result with no new record
         */
        public static PrepareResult alreadyUsable() {
            return new PrepareResult(true, null, null, null, null);
        }

        public static PrepareResult failure(IntegrityStatus status, IntegrityDetail detail, String message) {
            return new PrepareResult(false, null, status, detail, message);
        }

        public boolean isUsable() {
            return usable;
        }

        /**
         * Fail fast for callers that need a usable directory.
         *
         * @throws IntegrityCheckException when preparation did not produce a usable directory
         */
        public void requireUsable() throws IntegrityCheckException {
            if (!usable) {
                throw new IntegrityCheckException(failureMessage);
            }
        }

        public ArtifactExtractionRecord getRecord() {
            return record;
        }

        public IntegrityStatus getFailureStatus() {
            return failureStatus;
        }

        public IntegrityDetail getFailureDetail() {
            return failureDetail;
        }

        public String getFailureMessage() {
            return failureMessage;
        }
    }
}

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import lombok.NonNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Executes the cheap, read-only detection part of an integrity audit. It never downloads, never deletes and never
 * repairs; callers decide what to do with a non-verified result.
 */
public class ArtifactIntegrityAuditor {

    private static final Logger logger = LogManager.getLogger(ArtifactIntegrityAuditor.class);
    private static final String COMPONENT_KEY = "component";
    private static final String ARTIFACT_KEY = "artifactId";
    private static final String RELATIVE_PATH_KEY = "relativePath";

    private final ArtifactContentReader contentReader;

    @javax.inject.Inject
    public ArtifactIntegrityAuditor(@NonNull ArtifactContentReader contentReader) {
        this.contentReader = contentReader;
    }

    /**
     * Check the raw artifact bytes against the recipe digest.
     *
     * <p>Read failures, a read whose content changed mid-stream and a stable content mismatch are reported as
     * distinct results. File size and modification time are only used to detect change during the read; they are
     * never used to skip the content check.</p>
     *
     * @param componentIdentifier component identity
     * @param check               planned artifact-content check
     * @return result
     */
    public IntegrityCheckResult auditArtifactContent(@NonNull ComponentIdentifier componentIdentifier,
                                                     @NonNull IntegrityAuditPlan.PlannedCheck check) {
        DigestSpec spec = check.getDigestSpec();
        if (spec == null || !spec.usable()) {
            return metadataResult(componentIdentifier, check, spec);
        }

        Path path = check.getExpectedPath();
        BasicFileAttributes attributes;
        try {
            if (Files.isSymbolicLink(path)) {
                return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.SYMLINK,
                        "artifact path is a symbolic link; refusing to follow it");
            }
            attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            return missingOrUnreadable(componentIdentifier, check, path, e);
        }
        if (!attributes.isRegularFile()) {
            return result(componentIdentifier, check, IntegrityStatus.FILE_CORRUPTED,
                    IntegrityDetail.NOT_A_REGULAR_FILE, "expected a regular file");
        }

        ArtifactReadResult read;
        try {
            read = contentReader.read(path, spec.getAlgorithm());
        } catch (IOException | IllegalArgumentException e) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.READ_ERROR,
                    "failed to read artifact content: " + e.getClass().getSimpleName());
        }

        if (read.isChangedDuringRead()) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE,
                    IntegrityDetail.CHANGED_DURING_READ, "artifact changed while it was being read");
        }
        if (read.truncated()) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.TRUNCATED_READ,
                    String.format("read %d of %d bytes", read.getBytesRead(), read.getSizeAtStart()));
        }
        if (!spec.matches(read.getBase64Digest())) {
            return result(componentIdentifier, check, IntegrityStatus.FILE_CORRUPTED,
                    IntegrityDetail.CONTENT_MISMATCH, "artifact content does not match the recipe digest");
        }
        return result(componentIdentifier, check, IntegrityStatus.VERIFIED, IntegrityDetail.NONE,
                "artifact content matches the recipe digest");
    }

    private IntegrityCheckResult missingOrUnreadable(ComponentIdentifier componentIdentifier,
                                                     IntegrityAuditPlan.PlannedCheck check, Path path,
                                                     IOException cause) {
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            return result(componentIdentifier, check, IntegrityStatus.FILE_MISSING, IntegrityDetail.NONE,
                    "artifact file does not exist");
        }
        return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.READ_ERROR,
                "artifact file attributes could not be read: " + cause.getClass().getSimpleName());
    }

    private IntegrityCheckResult metadataResult(ComponentIdentifier componentIdentifier,
                                                IntegrityAuditPlan.PlannedCheck check, DigestSpec spec) {
        if (spec == null) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.LEGACY_NO_DIGEST,
                    "no digest metadata; content cannot be verified");
        }
        IntegrityStatus status = spec.getParseStatus();
        IntegrityDetail detail = spec.getParseDetail();
        String message = spec.getParseMessage() == null ? "digest metadata cannot be used" : spec.getParseMessage();
        return result(componentIdentifier, check, status, detail, message);
    }

    private IntegrityCheckResult result(ComponentIdentifier componentIdentifier,
                                        IntegrityAuditPlan.PlannedCheck check, IntegrityStatus status,
                                        IntegrityDetail detail, String message) {
        IntegrityCheckResult result = IntegrityCheckResult.builder().componentIdentifier(componentIdentifier)
                .artifactId(check.getArtifactId()).expectedPath(check.getExpectedPath())
                .relativePath(check.getRelativePath()).checkKind(check.getCheckKind()).status(status)
                .detail(detail).message(buildMessage(componentIdentifier, check, message)).build();
        String eventType = status == IntegrityStatus.VERIFIED ? "artifact-integrity-ok" : "artifact-integrity-fail";
        logger.atDebug().setEventType(eventType).kv(COMPONENT_KEY, componentIdentifier.toString())
                .kv(ARTIFACT_KEY, check.getArtifactId()).kv(RELATIVE_PATH_KEY, check.getRelativePath())
                .kv("status", status.name()).kv("detail", detail.name()).log("Artifact integrity check");
        return result;
    }

    private static String buildMessage(ComponentIdentifier componentIdentifier,
                                       IntegrityAuditPlan.PlannedCheck check, String detail) {
        return String.format("component %s, artifact %s, path %s: %s", componentIdentifier,
                check.getArtifactId(), check.getRelativePath(), detail);
    }
}

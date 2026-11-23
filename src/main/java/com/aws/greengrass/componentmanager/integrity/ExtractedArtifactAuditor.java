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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Audits an extracted directory against a trusted {@link ArtifactExtractionRecord}.
 *
 * <p>Existence is not evidence of integrity. A directory with no record, an untrusted record (source was never
 * verified) or a record that disagrees with the current recipe is reported as {@link IntegrityStatus#UNVERIFIABLE}
 * so the caller can re-prepare from a verified artifact instead of blessing whatever is on disk.</p>
 */
public class ExtractedArtifactAuditor {

    private static final Logger logger = LogManager.getLogger(ExtractedArtifactAuditor.class);
    private static final String COMPONENT_KEY = "component";
    private static final String ARTIFACT_KEY = "artifactId";

    private final ExtractionRecordStore recordStore;
    private final ArtifactContentReader contentReader;

    @javax.inject.Inject
    public ExtractedArtifactAuditor(@NonNull ExtractionRecordStore recordStore,
                                    @NonNull ArtifactContentReader contentReader) {
        this.recordStore = recordStore;
        this.contentReader = contentReader;
    }

    /**
     * Audit an extracted directory.
     *
     * @param componentIdentifier component identity
     * @param check               planned extracted-content check
     * @param sourceArtifactResult result of the raw artifact check for the same artifact. Extraction can only be
     *                             trusted when the source bytes are currently verified.
     * @return result
     */
    public IntegrityCheckResult auditExtraction(@NonNull ComponentIdentifier componentIdentifier,
                                                @NonNull IntegrityAuditPlan.PlannedCheck check,
                                                @NonNull IntegrityCheckResult sourceArtifactResult) {
        // A verified-extraction claim is only meaningful if the source artifact is currently verified.
        if (!sourceArtifactResult.isVerified()) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.SOURCE_UNVERIFIED,
                    "source artifact is not verified, extracted result cannot be trusted");
        }
        Path extractionRoot = check.getExtractionRoot();
        if (extractionRoot == null || Files.notExists(extractionRoot, LinkOption.NOFOLLOW_LINKS)) {
            return result(componentIdentifier, check, IntegrityStatus.FILE_MISSING, IntegrityDetail.NONE,
                    "extracted directory does not exist");
        }

        Optional<ArtifactExtractionRecord> loaded;
        try {
            loaded = recordStore.load(componentIdentifier, check.getArtifactId());
        } catch (IOException e) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.RECORD_INVALID,
                    "extraction record could not be read");
        } catch (ExtractionRecordStore.RecordInvalidException e) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.RECORD_INVALID,
                    "extraction record is invalid");
        }
        if (!loaded.isPresent()) {
            // A legacy directory produced by an older version has no record. Do not bless it by scanning.
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.RECORD_MISSING,
                    "no extraction record exists for this directory");
        }

        ArtifactExtractionRecord record = loaded.get();
        if (!record.isSourceVerified()) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.RECORD_INVALID,
                    "extraction record was created without a verified source artifact");
        }
        if (!recordMatchesRecipe(record, check)) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.RECORD_STALE,
                    "extraction record does not match the current recipe digest");
        }

        Set<String> excluded = new LinkedHashSet<>(record.getExcludedRuntimePaths());
        Map<String, ExtractedMember> expected = new TreeMap<>();
        for (ExtractedMember member : record.getMembers()) {
            expected.put(member.getRelativePath(), member);
        }

        Map<String, Path> actual = new TreeMap<>();
        try {
            collectActual(extractionRoot, actual, excluded);
        } catch (IOException e) {
            return result(componentIdentifier, check, IntegrityStatus.UNVERIFIABLE, IntegrityDetail.READ_ERROR,
                    "failed to walk extracted directory");
        }

        for (Map.Entry<String, ExtractedMember> entry : expected.entrySet()) {
            if (excluded.contains(entry.getKey())) {
                continue;
            }
            String relativePath = entry.getKey();
            Path actualPath = actual.get(relativePath);
            if (actualPath == null) {
                return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.FILE_MISSING,
                        IntegrityDetail.EXTRACTED_MEMBER_MISSING,
                        "recorded member is missing from the extracted directory");
            }
            if (Files.isSymbolicLink(actualPath)) {
                return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.FILE_CORRUPTED,
                        IntegrityDetail.EXTRACTED_SYMLINK, "member became a symbolic link");
            }
            ExtractedMember member = entry.getValue();
            if (member.getType() == ExtractedMember.MemberType.DIRECTORY) {
                if (!Files.isDirectory(actualPath, LinkOption.NOFOLLOW_LINKS)) {
                    return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.FILE_CORRUPTED,
                            IntegrityDetail.EXTRACTED_MEMBER_MODIFIED, "recorded directory is no longer a directory");
                }
                continue;
            }
            IntegrityCheckResult fileResult = verifyMemberFile(componentIdentifier, check, relativePath, member,
                    actualPath);
            if (fileResult != null) {
                return fileResult;
            }
        }

        for (String actualPath : actual.keySet()) {
            if (!expected.containsKey(actualPath) && !excluded.contains(actualPath)) {
                return memberResult(componentIdentifier, check, actualPath, IntegrityStatus.FILE_CORRUPTED,
                        IntegrityDetail.EXTRACTED_MEMBER_EXTRA,
                        "unexpected member is present in the extracted directory");
            }
        }

        IntegrityCheckResult verified = result(componentIdentifier, check, IntegrityStatus.VERIFIED,
                IntegrityDetail.NONE, "extracted members match the record");
        logger.atDebug().kv(COMPONENT_KEY, componentIdentifier.toString()).kv(ARTIFACT_KEY, check.getArtifactId())
                .kv("recordSchema", record.getSchemaVersion()).log("Extracted artifact integrity verified");
        return verified;
    }

    private IntegrityCheckResult verifyMemberFile(ComponentIdentifier componentIdentifier,
                                                  IntegrityAuditPlan.PlannedCheck check, String relativePath,
                                                  ExtractedMember member, Path actualPath) {
        if (!Files.isRegularFile(actualPath, LinkOption.NOFOLLOW_LINKS)) {
            return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.FILE_CORRUPTED,
                    IntegrityDetail.EXTRACTED_MEMBER_MODIFIED, "recorded file is no longer a regular file");
        }
        ArtifactReadResult read;
        try {
            read = contentReader.read(actualPath, ArtifactExtractionRecord.MEMBER_DIGEST_ALGORITHM);
        } catch (IOException | IllegalArgumentException e) {
            return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.UNVERIFIABLE,
                    IntegrityDetail.READ_ERROR, "failed to read extracted member");
        }
        if (read.isChangedDuringRead() || read.truncated()) {
            return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.UNVERIFIABLE,
                    IntegrityDetail.CHANGED_DURING_READ, "extracted member changed while it was being read");
        }
        if (member.getDigest() == null || !member.getDigest().equals(read.getBase64Digest())) {
            return memberResult(componentIdentifier, check, relativePath, IntegrityStatus.FILE_CORRUPTED,
                    IntegrityDetail.EXTRACTED_MEMBER_MODIFIED, "extracted member content has changed");
        }
        return null;
    }

    private static boolean recordMatchesRecipe(ArtifactExtractionRecord record, IntegrityAuditPlan.PlannedCheck check) {
        DigestSpec spec = check.getDigestSpec();
        if (spec == null || !spec.usable()) {
            return false;
        }
        if (record.getSourceAlgorithm() == null || !record.getSourceAlgorithm().equals(spec.getAlgorithm())) {
            return false;
        }
        return record.getSourceChecksum() != null && record.getSourceChecksum().equals(spec.getCanonicalChecksum());
    }

    private static void collectActual(Path extractionRoot, Map<String, Path> actual, Set<String> excluded)
            throws IOException {
        // walkFileTree without FOLLOW_LINKS visits symlinks as files and never descends through them, so a symlink
        // cannot smuggle in or hide members outside the extraction root.
        Files.walkFileTree(extractionRoot, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(extractionRoot)) {
                    actual.put(relative(extractionRoot, dir), dir);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                actual.put(relative(extractionRoot, file), file);
                return FileVisitResult.CONTINUE;
            }
        });
        // Exclusions are prefix based so a runtime-written subdirectory can be excluded as a unit.
        actual.keySet().removeIf(path -> isExcluded(path, excluded));
    }

    private static boolean isExcluded(String path, Set<String> excluded) {
        if (excluded.contains(path)) {
            return true;
        }
        for (String ex : excluded) {
            if (path.startsWith(ex.endsWith("/") ? ex : ex + "/")) {
                return true;
            }
        }
        return false;
    }

    private static String relative(Path root, Path child) {
        return root.relativize(child).toString().replace('\\', '/');
    }

    private IntegrityCheckResult memberResult(ComponentIdentifier componentIdentifier,
                                              IntegrityAuditPlan.PlannedCheck check, String relativePath,
                                              IntegrityStatus status, IntegrityDetail detail, String message) {
        return result(componentIdentifier, check, relativePath, status, detail, message);
    }

    private IntegrityCheckResult result(ComponentIdentifier componentIdentifier,
                                        IntegrityAuditPlan.PlannedCheck check, IntegrityStatus status,
                                        IntegrityDetail detail, String message) {
        return result(componentIdentifier, check, check.getRelativePath(), status, detail, message);
    }

    private IntegrityCheckResult result(ComponentIdentifier componentIdentifier,
                                        IntegrityAuditPlan.PlannedCheck check, String relativePath,
                                        IntegrityStatus status, IntegrityDetail detail, String message) {
        IntegrityCheckResult result = IntegrityCheckResult.builder().componentIdentifier(componentIdentifier)
                .artifactId(check.getArtifactId()).expectedPath(check.getExpectedPath()).relativePath(relativePath)
                .checkKind(IntegrityCheckKind.EXTRACTED_CONTENT).status(status).detail(detail)
                .message(String.format("component %s, artifact %s, path %s: %s", componentIdentifier,
                        check.getArtifactId(), relativePath, message)).build();
        logger.atDebug().kv(COMPONENT_KEY, componentIdentifier.toString()).kv(ARTIFACT_KEY, check.getArtifactId())
                .kv("relativePath", relativePath).kv("status", status.name()).kv("detail", detail.name())
                .log("Extracted artifact integrity check");
        return result;
    }
}

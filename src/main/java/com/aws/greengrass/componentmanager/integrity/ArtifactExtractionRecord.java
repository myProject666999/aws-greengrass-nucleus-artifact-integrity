/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Provenance record for one unpacked artifact. It ties the extracted directory to the artifact bytes that were
 * verified when the directory was produced, and lists exactly which members extraction created.
 *
 * <p>The record intentionally lives outside the extraction root. That keeps the extraction root free of audit
 * bookkeeping, so an audit never mistakes its own record for an extra extracted member.</p>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ArtifactExtractionRecord {

    /**
     * Bumped when the on-disk meaning changes. Readers must reject records they do not understand rather than guess.
     */
    public static final int CURRENT_SCHEMA_VERSION = 1;

    public static final String MEMBER_DIGEST_ALGORITHM = "SHA-256";

    int schemaVersion;

    String componentName;

    String componentVersion;

    /**
     * Artifact identity from the recipe, i.e. the artifact file name. Never a full URI.
     */
    String artifactId;

    /**
     * Algorithm declared by the recipe for the raw artifact bytes. May be null for legacy local recipes.
     */
    String sourceAlgorithm;

    /**
     * Base64 checksum declared by the recipe for the raw artifact bytes, or null for legacy local recipes.
     */
    String sourceChecksum;

    /**
     * Digest actually computed over the raw artifact that was unpacked. Null when the source could not be verified.
     */
    String verifiedSourceDigest;

    /**
     * False when the artifact bytes were not verified before extraction. Such a record is not a trust anchor.
     */
    boolean sourceVerified;

    String unarchiveMethod;

    /**
     * Algorithm used to hash each recorded member. Pinned in the record so a future default change cannot silently
     * reinterpret old records.
     */
    String memberDigestAlgorithm;

    long generatedAtEpochMillis;

    /**
     * Members created by extraction. Directories are included so empty directories are audited too.
     */
    @Builder.Default
    List<ExtractedMember> members = Collections.emptyList();

    /**
     * Paths relative to the extraction root that are expected to be written at runtime and must not be treated as
     * extraction pollution. Empty by default.
     */
    @Builder.Default
    Set<String> excludedRuntimePaths = Collections.emptySet();
}

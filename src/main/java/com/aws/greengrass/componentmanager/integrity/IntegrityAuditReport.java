/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import lombok.Builder;
import lombok.Value;

import java.util.Collections;
import java.util.List;

/**
 * Aggregate output of one audit run, grouped so a caller can decide per artifact whether the artifact may be used.
 */
@Value
@Builder
public class IntegrityAuditReport {

    ComponentIdentifier componentIdentifier;

    /**
     * Result for every artifact-content check, in plan order.
     */
    @Builder.Default
    List<IntegrityCheckResult> artifactResults = Collections.emptyList();

    /**
     * Result for every extracted-content check, in plan order.
     */
    @Builder.Default
    List<IntegrityCheckResult> extractionResults = Collections.emptyList();

    /**
     * Check whether the raw content of an artifact verified.
     *
     * @param artifactId artifact identity from the recipe
     * @return true when the raw artifact content check verified for this artifact
     */
    public boolean artifactVerified(String artifactId) {
        return artifactResults.stream()
                .anyMatch(r -> r.getArtifactId().equals(artifactId) && r.isVerified());
    }

    /**
     * Check whether the extracted result of an artifact verified.
     *
     * @param artifactId artifact identity from the recipe
     * @return true when the extraction check verified for this artifact
     */
    public boolean extractionVerified(String artifactId) {
        return extractionResults.stream()
                .anyMatch(r -> r.getArtifactId().equals(artifactId) && r.isVerified());
    }

    /**
     * Check whether every planned check verified.
     *
     * @return true when every planned check verified
     */
    public boolean allVerified() {
        return artifactResults.stream().allMatch(IntegrityCheckResult::isVerified)
                && extractionResults.stream().allMatch(IntegrityCheckResult::isVerified);
    }
}

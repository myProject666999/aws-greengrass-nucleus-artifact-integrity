/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import lombok.NonNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs an {@link IntegrityAuditPlan} through the artifact and extraction auditors and returns a grouped report.
 *
 * <p>The executor is strictly offline and read-only: it never downloads, never deletes and never repairs. Whether a
 * failed audit leads to a re-download or a re-extraction is the caller's decision.</p>
 */
public class IntegrityAuditExecutor {

    private final ArtifactIntegrityAuditor artifactAuditor;
    private final ExtractedArtifactAuditor extractedAuditor;

    @javax.inject.Inject
    public IntegrityAuditExecutor(@NonNull ArtifactIntegrityAuditor artifactAuditor,
                                  @NonNull ExtractedArtifactAuditor extractedAuditor) {
        this.artifactAuditor = artifactAuditor;
        this.extractedAuditor = extractedAuditor;
    }

    /**
     * Execute every check in the plan.
     *
     * @param plan plan to execute
     * @return grouped report
     */
    public IntegrityAuditReport execute(@NonNull IntegrityAuditPlan plan) {
        ComponentIdentifier componentIdentifier = plan.getComponentIdentifier();
        List<IntegrityCheckResult> artifactResults = new ArrayList<>();
        List<IntegrityCheckResult> extractionResults = new ArrayList<>();
        Map<String, IntegrityCheckResult> lastArtifactResultByArtifact = new HashMap<>();

        for (IntegrityAuditPlan.PlannedCheck check : plan.getChecks()) {
            if (check.getCheckKind() == IntegrityCheckKind.ARTIFACT_CONTENT) {
                IntegrityCheckResult result = artifactAuditor.auditArtifactContent(componentIdentifier, check);
                artifactResults.add(result);
                lastArtifactResultByArtifact.put(check.getArtifactId(), result);
            }
        }
        for (IntegrityAuditPlan.PlannedCheck check : plan.getChecks()) {
            if (check.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT) {
                IntegrityCheckResult source = lastArtifactResultByArtifact.get(check.getArtifactId());
                if (source == null) {
                    source = IntegrityCheckResult.builder().componentIdentifier(componentIdentifier)
                            .artifactId(check.getArtifactId()).checkKind(IntegrityCheckKind.ARTIFACT_CONTENT)
                            .status(IntegrityStatus.UNVERIFIABLE).detail(IntegrityDetail.SOURCE_UNVERIFIED)
                            .message("no artifact content check was planned for this artifact").build();
                }
                extractionResults.add(extractedAuditor.auditExtraction(componentIdentifier, check, source));
            }
        }

        return IntegrityAuditReport.builder().componentIdentifier(componentIdentifier).artifactResults(artifactResults)
                .extractionResults(extractionResults).build();
    }
}

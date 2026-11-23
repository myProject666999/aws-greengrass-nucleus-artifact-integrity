/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import lombok.Builder;
import lombok.Value;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

/**
 * Declarative description of the checks that should be run for one component. Building the plan is pure and side
 * effect free, so it can be asserted in a test without touching the filesystem and can be handed to different
 * executors.
 */
@Value
@Builder
public class IntegrityAuditPlan {

    ComponentIdentifier componentIdentifier;

    @Builder.Default
    List<PlannedCheck> checks = Collections.emptyList();

    /**
     * One planned check. {@code expectedPath} is resolved from the recipe and the component store layout.
     */
    @Value
    @Builder
    public static class PlannedCheck {

        String artifactId;

        Path expectedPath;

        /**
         * Path relative to the artifact directory or extraction parent. Never contains a full URI.
         */
        String relativePath;

        IntegrityCheckKind checkKind;

        /**
         * Parsed recipe digest contract. For extraction checks this is the digest of the source artifact that the
         * extraction record must agree with.
         */
        DigestSpec digestSpec;

        /**
         * True when the recipe asks for this artifact to be unpacked, so an extraction check is expected as well.
         */
        boolean unarchived;

        /**
         * Extraction root for an unarchived artifact. Null when {@link #unarchived} is false.
         */
        Path extractionRoot;
    }
}

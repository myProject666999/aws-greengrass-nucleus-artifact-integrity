/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import lombok.Builder;
import lombok.Value;
import lombok.experimental.Accessors;

import java.nio.file.Path;

/**
 * Immutable result of one integrity check.
 *
 * <p>The message is intentionally built only from the component identity, the artifact identity and a relative path.
 * It never contains a download URI, credentials or file content.</p>
 */
@Value
@Builder
@Accessors(fluent = false)
public class IntegrityCheckResult {

    ComponentIdentifier componentIdentifier;

    /**
     * Recipe-level artifact identity. This is the artifact file name, never a full URI.
     */
    String artifactId;

    /**
     * Expected path of the object that was checked. May be absent for pure metadata checks.
     */
    Path expectedPath;

    /**
     * Path relative to the artifact directory or the extracted directory. Safe to log.
     */
    String relativePath;

    IntegrityCheckKind checkKind;

    IntegrityStatus status;

    IntegrityDetail detail;

    /**
     * Human readable explanation. Contains only component, artifact id and relative path.
     */
    String message;

    public boolean isVerified() {
        return status == IntegrityStatus.VERIFIED;
    }

    public boolean hasUnresolvedProblem() {
        return status != IntegrityStatus.VERIFIED;
    }
}

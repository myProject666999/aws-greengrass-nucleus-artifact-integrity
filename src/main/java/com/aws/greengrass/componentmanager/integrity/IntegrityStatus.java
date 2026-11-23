/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

/**
 * Outcome of one integrity check. The values are deliberately coarse: they answer whether the object may be used,
 * while {@link IntegrityDetail} explains why. In particular, {@link #UNVERIFIABLE} must never be read as
 * "verified" - it means the available metadata or I/O did not allow a conclusion.
 */
public enum IntegrityStatus {
    /**
     * The check was possible and the content matched the expected identity.
     */
    VERIFIED,

    /**
     * The expected file or directory, or a recorded member, does not exist.
     */
    FILE_MISSING,

    /**
     * The object exists and was read successfully but its content does not match.
     */
    FILE_CORRUPTED,

    /**
     * The recipe metadata is missing, partial, or not a valid digest encoding for the declared algorithm.
     */
    METADATA_INCOMPLETE,

    /**
     * The declared algorithm is not available in the running JVM.
     */
    ALGORITHM_UNSUPPORTED,

    /**
     * No trustworthy conclusion is possible: legacy metadata, absent provenance, unreadable content, or content that
     * changed while it was being read.
     */
    UNVERIFIABLE
}

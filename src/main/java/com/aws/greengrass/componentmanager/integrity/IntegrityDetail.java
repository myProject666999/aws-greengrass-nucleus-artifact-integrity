/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

/**
 * Machine readable reason that refines an {@link IntegrityStatus}. Callers can distinguish, for example, an illegal
 * Base64 digest from a digest whose decoded length does not match the algorithm, from a stable content mismatch.
 */
public enum IntegrityDetail {
    NONE,

    // Recipe metadata problems.
    METADATA_PARTIAL,
    DIGEST_INVALID_BASE64,
    DIGEST_LENGTH_MISMATCH,
    LEGACY_NO_DIGEST,
    ALGORITHM_UNSUPPORTED,

    // Raw artifact content problems.
    CONTENT_MISMATCH,
    READ_ERROR,
    CHANGED_DURING_READ,
    TRUNCATED_READ,
    NOT_A_REGULAR_FILE,
    SYMLINK,

    // Extracted result provenance problems.
    RECORD_MISSING,
    RECORD_INVALID,
    RECORD_STALE,
    EXTRACTED_MEMBER_MISSING,
    EXTRACTED_MEMBER_MODIFIED,
    EXTRACTED_MEMBER_EXTRA,
    EXTRACTED_SYMLINK,
    EXTRACTED_PATH_ESCAPE,

    // Preparation problems surfaced to the caller.
    PUBLISH_FAILED,
    SOURCE_UNVERIFIED
}

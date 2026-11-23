/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import lombok.Builder;
import lombok.Value;

/**
 * Outcome of reading one file while computing its digest.
 *
 * <p>It records enough information to tell a clean, stable read apart from a read that was truncated or from a file
 * that changed while it was being read. Callers must not treat a digest as trustworthy when {@code changedDuringRead}
 * is true or when {@code bytesRead} is smaller than {@code sizeAtStart}.</p>
 */
@Value
@Builder
public class ArtifactReadResult {

    long bytesRead;

    long sizeAtStart;

    long sizeAtEnd;

    boolean changedDuringRead;

    /**
     * Standard Base64 encoding of the raw digest bytes. Null when the read did not complete.
     */
    String base64Digest;

    public boolean truncated() {
        return bytesRead < sizeAtStart;
    }
}

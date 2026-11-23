/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * One member that extraction produced. Both directories and regular files are recorded so that a later audit can
 * detect missing members, modified members, replaced members and symlinks that appeared after extraction.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtractedMember {

    /**
     * Member type values persisted in the record.
     */
    public enum MemberType {
        FILE,
        DIRECTORY
    }

    /**
     * Path relative to the extraction root. Stored with forward slashes so the record is portable.
     */
    String relativePath;

    MemberType type;

    /**
     * Size in bytes. Only meaningful for files.
     */
    long size;

    /**
     * Base64 encoded SHA-256 of the member bytes. Only present for files.
     */
    String digest;
}

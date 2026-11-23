/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

/**
 * Category of an integrity check. It lets a caller tell a raw artifact byte-level verdict apart from a verdict about
 * the result of unpacking that artifact.
 */
public enum IntegrityCheckKind {
    /**
     * The bytes of the raw artifact compared with the digest declared in the recipe.
     */
    ARTIFACT_CONTENT,

    /**
     * The members and file contents of an unpacked artifact compared with the recorded unpack provenance.
     */
    EXTRACTED_CONTENT
}

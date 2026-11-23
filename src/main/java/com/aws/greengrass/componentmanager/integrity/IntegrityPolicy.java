/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

/**
 * Explicit switch for callers that want to enforce integrity before using artifacts. The default is the conservative
 * one: an unverified object blocks use. A caller that must stay compatible with legacy local recipes can opt into
 * {@link #ALLOW_UNVERIFIED}.
 */
public enum IntegrityPolicy {

    /**
     * An artifact or extracted directory may only be used when every applicable check verified.
     */
    REQUIRE_VERIFIED,

    /**
     * Legacy, unverifiable inputs (no recipe digest, or an extracted directory with no record) may be used, but a
     * result that proves corruption - a content mismatch or a modified/missing recorded member - still blocks use.
     * This is an explicit compatibility mode, not the default.
     */
    ALLOW_UNVERIFIED;

    /**
     * Decide whether a check status may be used under this policy.
     *
     * @param status check status
     * @return true when the policy allows use
     */
    public boolean allows(IntegrityStatus status) {
        if (status == IntegrityStatus.VERIFIED) {
            return true;
        }
        return this == ALLOW_UNVERIFIED && status == IntegrityStatus.UNVERIFIABLE;
    }

    /**
     * Decide whether a check result may be used under this policy.
     *
     * @param result check result
     * @return true when the policy allows use
     */
    public boolean allows(IntegrityCheckResult result) {
        return allows(result.getStatus());
    }
}

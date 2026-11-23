/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

/**
 * Raised when a caller bound to an audit result finds the object has been replaced or the audit says the object may
 * not be used. The message is safe to log: it carries only the component identity, the artifact identity and a
 * relative path.
 */
public class IntegrityCheckException extends Exception {

    private static final long serialVersionUID = 1L;

    public IntegrityCheckException(String message) {
        super(message);
    }

    public IntegrityCheckException(String message, Throwable cause) {
        super(message, cause);
    }
}

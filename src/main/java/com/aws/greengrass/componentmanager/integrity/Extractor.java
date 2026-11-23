/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Performs the actual unpack. It is a functional interface so production code can pass the existing
 * {@code Unarchiver} (which already enforces zip-slip safety) while tests pass a controllable stand-in.
 */
@FunctionalInterface
public interface Extractor {

    /**
     * Unpack {@code source} into {@code destination}.
     *
     * @param source      verified artifact file
     * @param destination empty staging directory
     * @throws IOException if unpacking fails or a member escapes the destination
     */
    void extract(Path source, Path destination) throws IOException;
}

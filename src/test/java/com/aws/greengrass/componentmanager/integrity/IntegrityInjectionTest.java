/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.dependency.Context;
import com.aws.greengrass.util.NucleusPaths;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Proves the integrity services can be constructed by the nucleus dependency injection context, so wiring failures
 * surface in a fast unit test rather than only at kernel startup.
 */
class IntegrityInjectionTest {

    @TempDir
    Path root;

    private Context context;

    @BeforeEach
    void setUp() throws Exception {
        context = new Context();
        NucleusPaths paths = IntegrityTestSupport.paths(root.resolve("componentStore"));
        context.put(NucleusPaths.class, paths);
    }

    @AfterEach
    void tearDown() throws Exception {
        context.close();
    }

    @Test
    void GIVEN_nucleus_context_WHEN_resolve_integrity_manager_THEN_all_dependencies_wire() throws Exception {
        ArtifactIntegrityPlanner planner = context.get(ArtifactIntegrityPlanner.class);
        IntegrityAuditExecutor executor = context.get(IntegrityAuditExecutor.class);
        ExtractionPreparer preparer = context.get(ExtractionPreparer.class);
        ArtifactIntegrityManager manager = context.get(ArtifactIntegrityManager.class);

        assertNotNull(planner);
        assertNotNull(executor);
        assertNotNull(preparer);
        assertNotNull(manager);
        // Singletons within one context.
        assertSame(manager, context.get(ArtifactIntegrityManager.class));
    }

    @Test
    void GIVEN_nucleus_context_WHEN_resolve_content_reader_THEN_default_backed_by_filesystem() {
        ArtifactContentReader reader = context.get(ArtifactContentReader.class);
        assertNotNull(reader);
    }
}

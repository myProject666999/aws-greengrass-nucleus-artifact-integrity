/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.amazon.aws.iot.greengrass.component.common.Unarchive;
import com.aws.greengrass.componentmanager.Unarchiver;
import com.aws.greengrass.componentmanager.models.ComponentArtifact;
import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.componentmanager.models.ComponentRecipe;
import com.aws.greengrass.testcommons.testutilities.GGExtension;
import com.aws.greengrass.util.NucleusPaths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.base64Digest;
import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.identifier;
import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.writeZip;
import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.zipEntries;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(GGExtension.class)
class ExtractionPreparationTest {

    private static final String SHA_256 = "SHA-256";

    @TempDir
    Path root;

    private NucleusPaths paths;
    private ArtifactIntegrityPlanner planner;
    private ArtifactContentReader.Default reader;

    @BeforeEach
    void setUp() throws Exception {
        paths = IntegrityTestSupport.paths(root.resolve("componentStore"));
        planner = new ArtifactIntegrityPlanner(paths);
        reader = new ArtifactContentReader.Default();
    }

    private ExtractionRecordStore recordStore() {
        return new ExtractionRecordStore(paths);
    }

    private ComponentArtifact writeZipArtifact(ComponentIdentifier id) throws Exception {
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        writeZip(zip, zipEntries());
        String checksum = base64Digest(Files.readAllBytes(zip), SHA_256);
        return ComponentArtifact.builder().artifactUri(new URI("greengrass:pkg.zip")).algorithm(SHA_256)
                .checksum(checksum).unarchive(Unarchive.ZIP).build();
    }

    private IntegrityCheckResult verifiedSource(ComponentIdentifier id) {
        return IntegrityCheckResult.builder().componentIdentifier(id).artifactId("pkg.zip")
                .checkKind(IntegrityCheckKind.ARTIFACT_CONTENT).status(IntegrityStatus.VERIFIED)
                .detail(IntegrityDetail.NONE).relativePath("pkg.zip").message("ok").build();
    }

    private IntegrityAuditPlan.PlannedCheck extractionCheck(ComponentIdentifier id, ComponentArtifact artifact)
            throws IOException {
        return planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).findFirst().get();
    }

    private Extractor unzipper() {
        Unarchiver unarchiver = new Unarchiver();
        return (source, dest) -> unarchiver.unarchive(Unarchive.ZIP, source.toFile(), dest);
    }

    // ---- publish / rollback -------------------------------------------------

    @Test
    void GIVEN_verified_extraction_exists_WHEN_ensure_trustworthy_THEN_not_re_unpacked() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);
        assertTrue(preparer.prepare(id, check, zip, verifiedSource(id), "ZIP", unzipper()).isUsable());

        AtomicBoolean extractorCalled = new AtomicBoolean(false);
        ExtractionPreparer.PrepareResult ensured = manager().prepareVerifiedExtraction(id, artifact, Unarchive.ZIP,
                (source, dest) -> {
                    extractorCalled.set(true);
                    unzipper().extract(source, dest);
                });

        assertTrue(ensured.isUsable());
        assertFalse(extractorCalled.get(), "an already-verified extraction must be reused, not re-unpacked");
        // No record is dropped by reuse either.
        assertTrue(Files.isRegularFile(recordStore().recordPath(id, "pkg.zip")));
    }

    @Test
    void GIVEN_successful_prepare_WHEN_publish_THEN_previous_result_replaced_and_backup_gone() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);

        ExtractionPreparer.PrepareResult first = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                unzipper());
        assertTrue(first.isUsable());
        Files.write(check.getExtractionRoot().resolve("old-marker"), "old".getBytes(StandardCharsets.UTF_8));

        ExtractionPreparer.PrepareResult second = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                unzipper());
        assertTrue(second.isUsable());
        // A fresh extraction replaces the directory, so the old marker is gone.
        assertFalse(Files.exists(check.getExtractionRoot().resolve("old-marker")));
        // No staging or backup directories are left behind.
        try (java.util.stream.Stream<Path> children = Files.list(check.getExtractionRoot().getParent())) {
            assertFalse(children.anyMatch(p -> p.getFileName().toString().startsWith(".staging-")
                    || p.getFileName().toString().startsWith(".backup-")));
        }
    }

    @Test
    void GIVEN_extraction_fails_WHEN_prepare_THEN_previous_result_preserved() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);

        ExtractionPreparer.PrepareResult first = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                unzipper());
        assertTrue(first.isUsable());
        Path marker = check.getExtractionRoot().resolve("bin/run.sh");
        assertTrue(Files.exists(marker));

        ExtractionPreparer.PrepareResult failing = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                (source, dest) -> {
                    // Write a partial file, then fail; the stage must be discarded and the old result kept.
                    Files.createDirectories(dest.resolve("bin"));
                    Files.write(dest.resolve("bin/run.sh"), "partial".getBytes(StandardCharsets.UTF_8));
                    throw new IOException("simulated extraction failure");
                });
        assertFalse(failing.isUsable());
        assertEquals(IntegrityDetail.PUBLISH_FAILED, failing.getFailureDetail());
        // The previous, verified result is still intact.
        assertEquals("echo hello", new String(Files.readAllBytes(marker), StandardCharsets.UTF_8));
        try (java.util.stream.Stream<Path> children = Files.list(check.getExtractionRoot().getParent())) {
            assertFalse(children.anyMatch(p -> p.getFileName().toString().startsWith(".staging-")));
        }
    }

    @Test
    void GIVEN_record_persist_fails_WHEN_prepare_THEN_directory_rolled_back() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);

        // First prepare succeeds and establishes a usable directory + record.
        ExtractionPreparer good = new ExtractionPreparer(recordStore(), reader);
        assertTrue(good.prepare(id, check, zip, verifiedSource(id), "ZIP", unzipper()).isUsable());
        Path marker = check.getExtractionRoot().resolve("bin/run.sh");
        assertTrue(Files.exists(marker));

        // A store whose save always fails simulates a persist failure after publish.
        ExtractionRecordStore failingStore = new ExtractionRecordStore(paths) {
            @Override
            public void save(ArtifactExtractionRecord record) throws IOException {
                throw new IOException("simulated record write failure");
            }
        };
        ExtractionPreparer preparer = new ExtractionPreparer(failingStore, reader);
        ExtractionPreparer.PrepareResult failed = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                unzipper());
        assertFalse(failed.isUsable());
        assertEquals(IntegrityDetail.PUBLISH_FAILED, failed.getFailureDetail());
        // The previous directory must have been restored, not left replaced by an unrecorded one.
        assertTrue(Files.exists(marker));
    }

    @Test
    void GIVEN_source_not_verified_WHEN_prepare_THEN_refused_and_old_result_untouched() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);

        IntegrityCheckResult unverified = IntegrityCheckResult.builder().componentIdentifier(id)
                .artifactId("pkg.zip").checkKind(IntegrityCheckKind.ARTIFACT_CONTENT)
                .status(IntegrityStatus.FILE_CORRUPTED).detail(IntegrityDetail.CONTENT_MISMATCH).build();
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);
        ExtractionPreparer.PrepareResult result = preparer.prepare(id, check, zip, unverified, "ZIP", unzipper());

        assertFalse(result.isUsable());
        assertEquals(IntegrityDetail.SOURCE_UNVERIFIED, result.getFailureDetail());
        // The planner resolves paths through NucleusPaths, which creates the (empty) extraction root as it does for
        // the existing unpack path. What must not happen is any extracted member or provenance record appearing.
        if (Files.exists(check.getExtractionRoot())) {
            try (java.util.stream.Stream<Path> children = Files.list(check.getExtractionRoot())) {
                assertFalse(children.findAny().isPresent());
            }
        }
        assertFalse(Files.exists(recordStore().recordPath(id, "pkg.zip")));
    }

    @Test
    void GIVEN_extractor_produces_symlink_WHEN_prepare_THEN_refused() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);

        ExtractionPreparer.PrepareResult result = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                (source, dest) -> {
                    Path escape = dest.getParent().resolveSibling("escape-target");
                    Files.createDirectories(escape);
                    Files.createSymbolicLink(dest.resolve("link"), escape);
                });
        assertFalse(result.isUsable());
        assertEquals(IntegrityDetail.PUBLISH_FAILED, result.getFailureDetail());
    }

    @Test
    void GIVEN_unarchiver_rejects_zip_slip_WHEN_prepare_THEN_fails_without_publishing() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        Map<String, byte[]> evil = new java.util.LinkedHashMap<>();
        evil.put("../escape.txt", "x".getBytes(StandardCharsets.UTF_8));
        writeZip(zip, evil);
        String checksum = base64Digest(Files.readAllBytes(zip), SHA_256);
        ComponentArtifact artifact = ComponentArtifact.builder().artifactUri(new URI("greengrass:pkg.zip"))
                .algorithm(SHA_256).checksum(checksum).unarchive(Unarchive.ZIP).build();
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);

        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);
        ExtractionPreparer.PrepareResult result = preparer.prepare(id, check, zip, verifiedSource(id), "ZIP",
                unzipper());
        assertFalse(result.isUsable());
        assertFalse(Files.exists(check.getExtractionRoot().getParent().resolve("escape.txt")));
    }

    // ---- revalidation and policy --------------------------------------------

    @Test
    void GIVEN_replaced_artifact_WHEN_revalidate_THEN_old_verified_conclusion_not_reused() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck artifactCheck = planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.ARTIFACT_CONTENT).findFirst().get();
        ArtifactIdentity identity = ArtifactIdentity.of(zip);

        // Replace the file with different content of the same length.
        byte[] tampered = Files.readAllBytes(zip);
        tampered[0] = (byte) (tampered[0] ^ 0xFF);
        Files.write(zip, tampered);

        ArtifactIntegrityManager manager = manager();
        IntegrityCheckResult result = manager.revalidateIfReplaced(id, artifactCheck, identity);
        assertEquals(IntegrityStatus.FILE_CORRUPTED, result.getStatus());
        assertEquals(IntegrityDetail.CONTENT_MISMATCH, result.getDetail());
    }

    @Test
    void GIVEN_unchanged_artifact_WHEN_revalidate_THEN_verified() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        Path zip = paths.artifactPath(id).resolve("pkg.zip");
        IntegrityAuditPlan.PlannedCheck artifactCheck = planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.ARTIFACT_CONTENT).findFirst().get();
        ArtifactIdentity identity = ArtifactIdentity.of(zip);

        IntegrityCheckResult result = manager().revalidateIfReplaced(id, artifactCheck, identity);
        assertEquals(IntegrityStatus.VERIFIED, result.getStatus());
    }

    @Test
    void GIVEN_policy_require_verified_WHEN_unverifiable_THEN_blocked() {
        IntegrityCheckResult unverifiable = IntegrityCheckResult.builder().artifactId("a")
                .status(IntegrityStatus.UNVERIFIABLE).detail(IntegrityDetail.LEGACY_NO_DIGEST).message("m").build();
        assertThrows(IntegrityCheckException.class,
                () -> ArtifactIntegrityManager.requireUsable(unverifiable, IntegrityPolicy.REQUIRE_VERIFIED));
    }

    @Test
    void GIVEN_policy_allow_unverified_WHEN_unverifiable_THEN_allowed_but_corruption_still_blocked() {
        IntegrityCheckResult unverifiable = IntegrityCheckResult.builder().artifactId("a")
                .status(IntegrityStatus.UNVERIFIABLE).detail(IntegrityDetail.LEGACY_NO_DIGEST).message("m").build();
        assertDoesNotThrow(() -> ArtifactIntegrityManager.requireUsable(unverifiable, IntegrityPolicy.ALLOW_UNVERIFIED));

        IntegrityCheckResult corrupted = IntegrityCheckResult.builder().artifactId("a")
                .status(IntegrityStatus.FILE_CORRUPTED).detail(IntegrityDetail.CONTENT_MISMATCH).message("m").build();
        assertThrows(IntegrityCheckException.class,
                () -> ArtifactIntegrityManager.requireUsable(corrupted, IntegrityPolicy.ALLOW_UNVERIFIED));
    }

    // ---- concurrency with cleanup/read --------------------------------------

    @Test
    void GIVEN_prepare_holds_component_lock_WHEN_another_operation_starts_THEN_it_waits() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeZipArtifact(id);
        ComponentRecipe recipe = ComponentRecipe.builder().componentName("Comp")
                .version(new com.vdurmont.semver4j.Semver("1.0.0")).artifacts(Collections.singletonList(artifact))
                .build();
        Path zip = paths.artifactPath(id).resolve("pkg.zip");

        CountDownLatch extractorEntered = new CountDownLatch(1);
        CountDownLatch releaseExtractor = new CountDownLatch(1);
        ArtifactIntegrityManager manager = manager();

        Extractor blocking = (source, dest) -> {
            extractorEntered.countDown();
            try {
                assertTrue(releaseExtractor.await(10, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            unzipper().extract(source, dest);
        };

        java.util.concurrent.atomic.AtomicReference<IOException> firstFailure =
                new java.util.concurrent.atomic.AtomicReference<>();
        Thread first = new Thread(() -> {
            try {
                manager.auditAndEnforce(id, recipe, IntegrityPolicy.REQUIRE_VERIFIED,
                        Collections.singletonMap("pkg.zip",
                                ArtifactIntegrityManager.rePrepare(zip, blocking, Unarchive.ZIP)));
            } catch (IOException e) {
                firstFailure.set(e);
            }
        });
        first.start();
        assertTrue(extractorEntered.await(5, TimeUnit.SECONDS), "first operation should enter extraction");

        // While the first operation holds the per-component lock, a second operation on the same component must not
        // complete. It is released only after the first finishes.
        AtomicBoolean secondCompletedWhileFirstHeld = new AtomicBoolean(false);
        java.util.concurrent.atomic.AtomicReference<IOException> secondFailure =
                new java.util.concurrent.atomic.AtomicReference<>();
        Thread second = new Thread(() -> {
            try {
                manager.audit(id, recipe);
                secondCompletedWhileFirstHeld.set(true);
            } catch (IOException e) {
                secondFailure.set(e);
            }
        });
        second.start();
        // Give the second thread time to attempt the lock; it should still be blocked.
        Thread.sleep(300);
        assertFalse(secondCompletedWhileFirstHeld.get(), "second operation must wait for the component lock");

        releaseExtractor.countDown();
        first.join(TimeUnit.SECONDS.toMillis(10));
        second.join(TimeUnit.SECONDS.toMillis(10));
        assertFalse(first.isAlive());
        assertFalse(second.isAlive());
        assertNull(firstFailure.get());
        assertNull(secondFailure.get());
        assertTrue(secondCompletedWhileFirstHeld.get());
        // After both complete, the extraction verifies.
        assertTrue(manager.audit(id, recipe).extractionVerified("pkg.zip"));
    }

    // ---- helpers ------------------------------------------------------------

    private ArtifactIntegrityManager manager() throws IOException {
        IntegrityAuditExecutor executor = new IntegrityAuditExecutor(new ArtifactIntegrityAuditor(reader),
                new ExtractedArtifactAuditor(recordStore(), reader));
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);
        return new ArtifactIntegrityManager(planner, executor, preparer);
    }
}

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
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.base64Digest;
import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.identifier;
import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.writeZip;
import static com.aws.greengrass.componentmanager.integrity.IntegrityTestSupport.zipEntries;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(GGExtension.class)
class ArtifactIntegrityAuditTest {

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

    private ArtifactIntegrityAuditor auditor() {
        return new ArtifactIntegrityAuditor(reader);
    }

    private ArtifactIntegrityAuditor auditor(ArtifactContentReader customReader) {
        return new ArtifactIntegrityAuditor(customReader);
    }

    private Path artifactDir(ComponentIdentifier id) throws IOException {
        return paths.artifactPath(id);
    }

    private ComponentArtifact artifact(String filename, String algorithm, String checksum) throws Exception {
        return ComponentArtifact.builder().artifactUri(new URI("greengrass:" + filename)).algorithm(algorithm)
                .checksum(checksum).build();
    }

    // ---- DigestSpec contract -------------------------------------------------

    @Test
    void GIVEN_canonical_sha256_digest_WHEN_parse_THEN_usable() throws Exception {
        String digest = base64Digest("hello", SHA_256);
        DigestSpec spec = DigestSpec.parse(SHA_256, digest);
        assertTrue(spec.usable());
        assertEquals(IntegrityStatus.VERIFIED, spec.getParseStatus());
        assertTrue(spec.matches(digest));
    }

    @Test
    void GIVEN_hex_digest_WHEN_parse_THEN_rejected_not_silently_reinterpreted() {
        // The existing contract is Base64; a hex string is a different, unsupported encoding even though it is valid
        // Base64 characters only by accident. Decoding yields the wrong length, which must be reported.
        DigestSpec spec = DigestSpec.parse(SHA_256,
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f00aa1122");
        assertFalse(spec.usable());
        assertTrue(spec.getParseStatus() == IntegrityStatus.METADATA_INCOMPLETE
                || spec.getParseStatus() == IntegrityStatus.UNVERIFIABLE);
        assertTrue(spec.getParseDetail() == IntegrityDetail.DIGEST_LENGTH_MISMATCH
                || spec.getParseDetail() == IntegrityDetail.DIGEST_INVALID_BASE64);
    }

    @Test
    void GIVEN_invalid_base64_WHEN_parse_THEN_invalid_base64_detail() {
        DigestSpec spec = DigestSpec.parse(SHA_256, "not base64!!!");
        assertFalse(spec.usable());
        assertEquals(IntegrityStatus.METADATA_INCOMPLETE, spec.getParseStatus());
        assertEquals(IntegrityDetail.DIGEST_INVALID_BASE64, spec.getParseDetail());
    }

    @Test
    void GIVEN_valid_base64_of_wrong_length_WHEN_parse_THEN_length_mismatch() {
        // 4 base64 bytes decode to 3 bytes; SHA-256 expects 32.
        DigestSpec spec = DigestSpec.parse(SHA_256, "AAAA");
        assertFalse(spec.usable());
        assertEquals(IntegrityDetail.DIGEST_LENGTH_MISMATCH, spec.getParseDetail());
    }

    @Test
    void GIVEN_unknown_algorithm_WHEN_parse_THEN_algorithm_unsupported() {
        DigestSpec spec = DigestSpec.parse("NOT-A-DIGEST", "AAAA");
        assertFalse(spec.usable());
        assertEquals(IntegrityStatus.ALGORITHM_UNSUPPORTED, spec.getParseStatus());
        assertEquals(IntegrityDetail.ALGORITHM_UNSUPPORTED, spec.getParseDetail());
    }

    @Test
    void GIVEN_only_algorithm_WHEN_parse_THEN_metadata_partial() {
        DigestSpec spec = DigestSpec.parse(SHA_256, null);
        assertEquals(IntegrityStatus.METADATA_INCOMPLETE, spec.getParseStatus());
        assertEquals(IntegrityDetail.METADATA_PARTIAL, spec.getParseDetail());
    }

    @Test
    void GIVEN_only_checksum_WHEN_parse_THEN_metadata_partial() throws Exception {
        DigestSpec spec = DigestSpec.parse(null, base64Digest("x", SHA_256));
        assertEquals(IntegrityStatus.METADATA_INCOMPLETE, spec.getParseStatus());
        assertEquals(IntegrityDetail.METADATA_PARTIAL, spec.getParseDetail());
    }

    @Test
    void GIVEN_no_digest_WHEN_parse_THEN_legacy_unverifiable_not_corrupt() {
        DigestSpec spec = DigestSpec.parse(null, null);
        assertEquals(IntegrityStatus.UNVERIFIABLE, spec.getParseStatus());
        assertEquals(IntegrityDetail.LEGACY_NO_DIGEST, spec.getParseDetail());
    }

    // ---- Artifact content audit ---------------------------------------------

    @Test
    void GIVEN_matching_artifact_WHEN_audit_THEN_verified() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        byte[] content = "artifact-bytes".getBytes(StandardCharsets.UTF_8);
        Files.createDirectories(artifactDir(id));
        Files.write(artifactDir(id).resolve("artifact.txt"), content);
        ComponentArtifact artifact = artifact("artifact.txt", SHA_256, base64Digest(content, SHA_256));

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor().auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.VERIFIED, result.getStatus());
        assertTrue(result.isVerified());
        assertEquals("artifact.txt", result.getRelativePath());
    }

    @Test
    void GIVEN_same_size_corruption_WHEN_audit_THEN_content_mismatch_not_missing() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        byte[] good = "AAAAAAAA".getBytes(StandardCharsets.UTF_8);
        byte[] bad = "BBBBBBBB".getBytes(StandardCharsets.UTF_8);
        Files.createDirectories(artifactDir(id));
        Files.write(artifactDir(id).resolve("artifact.txt"), bad);
        ComponentArtifact artifact = artifact("artifact.txt", SHA_256, base64Digest(good, SHA_256));

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor().auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.FILE_CORRUPTED, result.getStatus());
        assertEquals(IntegrityDetail.CONTENT_MISMATCH, result.getDetail());
    }

    @Test
    void GIVEN_missing_artifact_WHEN_audit_THEN_file_missing() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        Files.createDirectories(artifactDir(id));
        ComponentArtifact artifact = artifact("artifact.txt", SHA_256, base64Digest("x", SHA_256));

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor().auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.FILE_MISSING, result.getStatus());
    }

    @Test
    void GIVEN_local_recipe_without_digest_WHEN_audit_THEN_unverifiable_not_corrupt() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        Files.createDirectories(artifactDir(id));
        Files.write(artifactDir(id).resolve("artifact.txt"), "whatever".getBytes(StandardCharsets.UTF_8));
        ComponentArtifact artifact = artifact("artifact.txt", null, null);

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor().auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.LEGACY_NO_DIGEST, result.getDetail());
        assertFalse(result.isVerified());
    }

    @Test
    void GIVEN_truncated_read_WHEN_audit_THEN_truncated_detail_not_mismatch() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        byte[] content = "artifact-bytes".getBytes(StandardCharsets.UTF_8);
        Files.createDirectories(artifactDir(id));
        Path file = artifactDir(id).resolve("artifact.txt");
        Files.write(file, content);
        ComponentArtifact artifact = artifact("artifact.txt", SHA_256, base64Digest(content, SHA_256));

        String digest = base64Digest(content, SHA_256);
        ArtifactContentReader truncating = (path, algorithm) -> ArtifactReadResult.builder()
                .bytesRead(content.length - 3).sizeAtStart(content.length).sizeAtEnd(content.length)
                .changedDuringRead(false).base64Digest(digest).build();

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor(truncating).auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.TRUNCATED_READ, result.getDetail());
    }

    @Test
    void GIVEN_changed_during_read_WHEN_audit_THEN_changed_detail() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        byte[] content = "artifact-bytes".getBytes(StandardCharsets.UTF_8);
        Files.createDirectories(artifactDir(id));
        Path file = artifactDir(id).resolve("artifact.txt");
        Files.write(file, content);
        ComponentArtifact artifact = artifact("artifact.txt", SHA_256, base64Digest(content, SHA_256));

        String digest = base64Digest(content, SHA_256);
        ArtifactContentReader changing = (path, algorithm) -> ArtifactReadResult.builder()
                .bytesRead(content.length).sizeAtStart(content.length).sizeAtEnd(content.length + 1)
                .changedDuringRead(true).base64Digest(digest).build();

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor(changing).auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.CHANGED_DURING_READ, result.getDetail());
    }

    @Test
    void GIVEN_same_size_and_mtime_WHEN_audit_THEN_content_still_checked() throws Exception {
        // A tampered file with the same size must still be detected; size cannot short-circuit the content check.
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        byte[] good = "abcd".getBytes(StandardCharsets.UTF_8);
        Files.createDirectories(artifactDir(id));
        Path file = artifactDir(id).resolve("artifact.txt");
        Files.write(file, good);
        long mtime = Files.getLastModifiedTime(file).toMillis();
        Files.write(file, "abce".getBytes(StandardCharsets.UTF_8));
        Files.setLastModifiedTime(file, java.nio.file.attribute.FileTime.fromMillis(mtime));
        ComponentArtifact artifact = artifact("artifact.txt", SHA_256, base64Digest(good, SHA_256));

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        IntegrityCheckResult result = auditor().auditArtifactContent(id, plan.getChecks().get(0));

        assertEquals(IntegrityStatus.FILE_CORRUPTED, result.getStatus());
        assertEquals(IntegrityDetail.CONTENT_MISMATCH, result.getDetail());
    }

    @Test
    void GIVEN_error_message_WHEN_audit_THEN_no_uri_or_content_leaked() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        Files.createDirectories(artifactDir(id));
        ComponentArtifact artifact = ComponentArtifact.builder()
                .artifactUri(new URI("https://signed.example.com/path?X-Amz-Signature=SECRET"))
                .algorithm(SHA_256).checksum(base64Digest("x", SHA_256)).build();

        IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(id)
                .checks(planner.planArtifact(id, artifact)).build();
        // An unknown scheme is not planned as a file artifact at all.
        assertTrue(plan.getChecks().isEmpty());
    }

    // ---- Extraction audit ---------------------------------------------------

    private ExtractionRecordStore recordStore() {
        return new ExtractionRecordStore(paths);
    }

    private IntegrityCheckResult verifiedSource(ComponentIdentifier id, String artifactId) {
        return IntegrityCheckResult.builder().componentIdentifier(id).artifactId(artifactId)
                .checkKind(IntegrityCheckKind.ARTIFACT_CONTENT).status(IntegrityStatus.VERIFIED)
                .detail(IntegrityDetail.NONE).relativePath(artifactId).message("ok").build();
    }

    private ComponentArtifact zipArtifact(String name) throws Exception {
        return ComponentArtifact.builder().artifactUri(new URI("greengrass:" + name)).algorithm(SHA_256)
                .checksum(null).unarchive(Unarchive.ZIP).build();
    }

    /**
     * Write the standard zip and return an artifact carrying its real checksum, so preparation is allowed.
     */
    private ComponentArtifact writeSampleZipArtifact(ComponentIdentifier id) throws Exception {
        Path zip = artifactDir(id).resolve("pkg.zip");
        writeZip(zip, zipEntries());
        String checksum = base64Digest(Files.readAllBytes(zip), SHA_256);
        return ComponentArtifact.builder().artifactUri(new URI("greengrass:pkg.zip")).algorithm(SHA_256)
                .checksum(checksum).unarchive(Unarchive.ZIP).build();
    }

    @Test
    void GIVEN_prepared_extraction_WHEN_audit_THEN_verified_and_record_outside_root() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        Path zip = artifactDir(id).resolve("pkg.zip");
        Map<String, byte[]> entries = zipEntries();
        writeZip(zip, entries);
        String checksum = base64Digest(Files.readAllBytes(zip), SHA_256);
        ComponentArtifact artifact = ComponentArtifact.builder().artifactUri(new URI("greengrass:pkg.zip"))
                .algorithm(SHA_256).checksum(checksum)
                .unarchive(Unarchive.ZIP).build();

        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);
        IntegrityAuditPlan.PlannedCheck extractionCheck = planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).findFirst().get();
        Unarchiver unarchiver = new Unarchiver();
        ExtractionPreparer.PrepareResult prepared = preparer.prepare(id, extractionCheck, zip,
                verifiedSource(id, "pkg.zip"), "ZIP",
                (source, dest) -> unarchiver.unarchive(Unarchive.ZIP,
                        source.toFile(), dest));
        assertTrue(prepared.isUsable());

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));
        assertEquals(IntegrityStatus.VERIFIED, result.getStatus());

        // The record must not live inside the extraction root, or it would look like an extra member.
        Path extractionRoot = extractionCheck.getExtractionRoot();
        assertFalse(Files.exists(extractionRoot.resolve("pkg.record.json")));
        Path recordPath = recordStore().recordPath(id, "pkg.zip");
        assertTrue(Files.isRegularFile(recordPath));
    }

    @Test
    void GIVEN_no_record_WHEN_audit_extraction_THEN_unverifiable_record_missing() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        Path extractionRoot = paths.unarchiveArtifactPath(id, "pkg");
        Files.createDirectories(extractionRoot);
        Files.write(extractionRoot.resolve("run.sh"), "x".getBytes(StandardCharsets.UTF_8));
        ComponentArtifact artifact = zipArtifact("pkg.zip");
        IntegrityAuditPlan.PlannedCheck extractionCheck = planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).findFirst().get();

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));

        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.RECORD_MISSING, result.getDetail());
    }

    @Test
    void GIVEN_source_not_verified_WHEN_audit_extraction_THEN_unverifiable() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = zipArtifact("pkg.zip");
        IntegrityAuditPlan.PlannedCheck extractionCheck = planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).findFirst().get();
        IntegrityCheckResult corruptSource = IntegrityCheckResult.builder().componentIdentifier(id)
                .artifactId("pkg.zip").checkKind(IntegrityCheckKind.ARTIFACT_CONTENT)
                .status(IntegrityStatus.FILE_CORRUPTED).detail(IntegrityDetail.CONTENT_MISMATCH).build();

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, corruptSource);
        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.SOURCE_UNVERIFIED, result.getDetail());
    }

    @Test
    void GIVEN_recorded_member_deleted_WHEN_audit_extraction_THEN_member_missing() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeSampleZipArtifact(id);
        prepareExtraction(id, artifact);
        IntegrityAuditPlan.PlannedCheck extractionCheck = extractionCheck(id, artifact);
        Files.delete(extractionCheck.getExtractionRoot().resolve("conf/config.json"));

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));

        assertEquals(IntegrityStatus.FILE_MISSING, result.getStatus());
        assertEquals(IntegrityDetail.EXTRACTED_MEMBER_MISSING, result.getDetail());
    }

    @Test
    void GIVEN_recorded_member_modified_WHEN_audit_extraction_THEN_modified() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeSampleZipArtifact(id);
        prepareExtraction(id, artifact);
        IntegrityAuditPlan.PlannedCheck extractionCheck = extractionCheck(id, artifact);
        Files.write(extractionCheck.getExtractionRoot().resolve("bin/run.sh"),
                "echo tampered".getBytes(StandardCharsets.UTF_8));

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));

        assertEquals(IntegrityStatus.FILE_CORRUPTED, result.getStatus());
        assertEquals(IntegrityDetail.EXTRACTED_MEMBER_MODIFIED, result.getDetail());
    }

    @Test
    void GIVEN_extra_member_WHEN_audit_extraction_THEN_extra_reported() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeSampleZipArtifact(id);
        prepareExtraction(id, artifact);
        IntegrityAuditPlan.PlannedCheck extractionCheck = extractionCheck(id, artifact);
        Files.write(extractionCheck.getExtractionRoot().resolve("planted.bin"),
                "p".getBytes(StandardCharsets.UTF_8));

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));

        assertEquals(IntegrityStatus.FILE_CORRUPTED, result.getStatus());
        assertEquals(IntegrityDetail.EXTRACTED_MEMBER_EXTRA, result.getDetail());
    }

    @Test
    void GIVEN_excluded_runtime_paths_WHEN_audit_extraction_THEN_not_counted_as_pollution() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeSampleZipArtifact(id);
        ExtractionPreparer.PrepareResult prepared = prepareExtraction(id, artifact);
        IntegrityAuditPlan.PlannedCheck extractionCheck = extractionCheck(id, artifact);

        // Rewrite the record to declare a runtime directory as excluded, then create it.
        ArtifactExtractionRecord record = prepared.getRecord();
        record.setExcludedRuntimePaths(Collections.singleton("runtime"));
        recordStore().save(record);
        Files.createDirectories(extractionCheck.getExtractionRoot().resolve("runtime/cache"));
        Files.write(extractionCheck.getExtractionRoot().resolve("runtime/cache/state"), "s".getBytes(
                StandardCharsets.UTF_8));

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));
        assertEquals(IntegrityStatus.VERIFIED, result.getStatus());
    }

    @Test
    void GIVEN_record_stale_against_recipe_WHEN_audit_extraction_THEN_record_stale() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact preparedUnder = writeSampleZipArtifact(id);
        prepareExtraction(id, preparedUnder);

        // Audit under a recipe whose digest differs from the one bound into the record.
        String differentChecksum = base64Digest("a different artifact", SHA_256);
        ComponentArtifact recipeChanged = ComponentArtifact.builder()
                .artifactUri(new URI("greengrass:pkg.zip")).algorithm(SHA_256).checksum(differentChecksum)
                .unarchive(Unarchive.ZIP).build();
        IntegrityAuditPlan.PlannedCheck extractionCheck = extractionCheck(id, recipeChanged);

        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));
        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.RECORD_STALE, result.getDetail());
    }

    @Test
    void GIVEN_untrusted_record_source_verified_false_WHEN_audit_extraction_THEN_record_invalid() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact artifact = writeSampleZipArtifact(id);
        ExtractionPreparer.PrepareResult prepared = prepareExtraction(id, artifact);
        ArtifactExtractionRecord record = prepared.getRecord();
        record.setSourceVerified(false);
        recordStore().save(record);

        IntegrityAuditPlan.PlannedCheck extractionCheck = extractionCheck(id, artifact);
        ExtractedArtifactAuditor auditor = new ExtractedArtifactAuditor(recordStore(), reader);
        IntegrityCheckResult result = auditor.auditExtraction(id, extractionCheck, verifiedSource(id, "pkg.zip"));
        assertEquals(IntegrityStatus.UNVERIFIABLE, result.getStatus());
        assertEquals(IntegrityDetail.RECORD_INVALID, result.getDetail());
    }

    // ---- Planner ------------------------------------------------------------

    @Test
    void GIVEN_recipe_with_zip_artifact_WHEN_plan_THEN_two_checks_with_distinct_kinds() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentRecipe recipe = ComponentRecipe.builder().componentName("Comp").version(new com.vdurmont.semver4j
                .Semver("1.0.0")).artifacts(Arrays.asList(
                ComponentArtifact.builder().artifactUri(new URI("greengrass:pkg.zip")).algorithm(SHA_256)
                        .checksum(base64Digest("x", SHA_256))
                        .unarchive(Unarchive.ZIP).build(),
                ComponentArtifact.builder().artifactUri(new URI("s3://bucket/plain.txt")).algorithm(SHA_256)
                        .checksum(base64Digest("y", SHA_256)).build())).build();

        IntegrityAuditPlan plan = planner.plan(id, recipe);
        assertEquals(3, plan.getChecks().size());
        assertEquals(2, plan.getChecks().stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.ARTIFACT_CONTENT).count());
        assertEquals(1, plan.getChecks().stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).count());
    }

    @Test
    void GIVEN_docker_artifact_WHEN_plan_THEN_no_file_checks() throws Exception {
        ComponentIdentifier id = identifier("Comp", "1.0.0");
        ComponentArtifact docker = ComponentArtifact.builder()
                .artifactUri(new URI("docker:public.ecr.aws/x/y:1")).build();
        assertTrue(planner.planArtifact(id, docker).isEmpty());
    }

    // ---- helpers ------------------------------------------------------------

    private ExtractionPreparer.PrepareResult prepareExtraction(ComponentIdentifier id, ComponentArtifact artifact)
            throws Exception {
        Path zip = artifactDir(id).resolve("pkg.zip");
        ExtractionPreparer preparer = new ExtractionPreparer(recordStore(), reader);
        IntegrityAuditPlan.PlannedCheck check = extractionCheck(id, artifact);
        Unarchiver unarchiver = new Unarchiver();
        return preparer.prepare(id, check, zip, verifiedSource(id, "pkg.zip"), "ZIP",
                (source, dest) -> unarchiver.unarchive(
                        Unarchive.ZIP, source.toFile(), dest));
    }

    private IntegrityAuditPlan.PlannedCheck extractionCheck(ComponentIdentifier id, ComponentArtifact artifact)
            throws Exception {
        return planner.planArtifact(id, artifact).stream()
                .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).findFirst().get();
    }
}

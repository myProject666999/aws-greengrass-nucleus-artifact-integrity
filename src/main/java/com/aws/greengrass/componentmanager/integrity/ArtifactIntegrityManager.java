/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.amazon.aws.iot.greengrass.component.common.Unarchive;
import com.aws.greengrass.componentmanager.models.ComponentArtifact;
import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.componentmanager.models.ComponentRecipe;
import com.aws.greengrass.logging.api.Logger;
import com.aws.greengrass.logging.impl.LogManager;
import com.aws.greengrass.util.LockFactory;
import com.aws.greengrass.util.LockScope;
import lombok.NonNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;
import javax.inject.Inject;

/**
 * The boundary that decides whether an on-device artifact and its extracted result may be used.
 *
 * <p>It is offline and read-only by itself: it never downloads, never deletes and never rewrites the download retry or
 * resume logic. Re-preparation, when the caller supplies it, unpacks from an already-verified artifact into an
 * isolated staging directory and publishes only after every check succeeds.</p>
 *
 * <p>A conclusion is bound to the {@link ArtifactIdentity} of the object inspected. Before a caller reuses a prior
 * conclusion it can call {@link #revalidateIfReplaced}; if the object was replaced the conclusion is discarded and the
 * object is re-verified once, or refused when the policy does not allow the new state.</p>
 *
 * <p>Audits, re-preparation and cleanup are serialized per component with an in-process lock. That lock orders these
 * operations inside this JVM. It does not make a directory rename atomic against an external process on every
 * filesystem; a publish that cannot complete is reported as a failure rather than assumed successful.</p>
 */
public class ArtifactIntegrityManager {

    private static final Logger logger = LogManager.getLogger(ArtifactIntegrityManager.class);

    private final ArtifactIntegrityPlanner planner;
    private final IntegrityAuditExecutor executor;
    private final ExtractionPreparer preparer;
    private final Map<String, Lock> componentLocks = new HashMap<>();

    /**
     * Create the boundary service.
     *
     * @param planner   audit planner
     * @param executor  audit executor
     * @param preparer  extraction preparer
     */
    @Inject
    public ArtifactIntegrityManager(@NonNull ArtifactIntegrityPlanner planner,
                                    @NonNull IntegrityAuditExecutor executor,
                                    @NonNull ExtractionPreparer preparer) {
        this.planner = planner;
        this.executor = executor;
        this.preparer = preparer;
    }

    /**
     * Audit a component. This overload never re-prepares.
     *
     * @param componentIdentifier component identity
     * @param recipe              resolved recipe
     * @return report
     * @throws IOException if a store path cannot be resolved
     */
    public IntegrityAuditReport audit(@NonNull ComponentIdentifier componentIdentifier,
                                      @NonNull ComponentRecipe recipe) throws IOException {
        try (LockScope lock = LockScope.lock(lockFor(componentIdentifier))) {
            return executor.execute(planner.plan(componentIdentifier, recipe));
        }
    }

    /**
     * Audit a component and re-prepare any extracted directory the policy does not allow, provided a re-preparation
     * callback exists for that artifact and its source artifact currently verifies.
     *
     * <p>Extraction that already verified is left untouched. Extraction that failed for a reason that a fresh
     * extraction cannot fix - a source artifact that does not verify - is not re-prepared; it stays failing so the
     * caller can decide to repair the download.</p>
     *
     * @param componentIdentifier component identity
     * @param recipe              resolved recipe
     * @param policy              enforcement policy
     * @param rePreparations      callbacks keyed by artifact id
     * @return final report after any re-preparation
     * @throws IOException if a store path cannot be resolved
     */
    public IntegrityAuditReport auditAndEnforce(@NonNull ComponentIdentifier componentIdentifier,
                                                @NonNull ComponentRecipe recipe,
                                                @NonNull IntegrityPolicy policy,
                                                @NonNull Map<String, RePreparation> rePreparations)
            throws IOException {
        try (LockScope lock = LockScope.lock(lockFor(componentIdentifier))) {
            IntegrityAuditPlan plan = planner.plan(componentIdentifier, recipe);
            IntegrityAuditReport report = executor.execute(plan);

            Map<String, IntegrityCheckResult> sourceByArtifact = new HashMap<>();
            for (IntegrityCheckResult result : report.getArtifactResults()) {
                sourceByArtifact.put(result.getArtifactId(), result);
            }

            boolean rePreparedAny = false;
            for (IntegrityCheckResult extraction : report.getExtractionResults()) {
                if (policy.allows(extraction)) {
                    continue;
                }
                RePreparation callback = rePreparations.get(extraction.getArtifactId());
                IntegrityCheckResult source = sourceByArtifact.get(extraction.getArtifactId());
                if (callback == null || source == null || !source.isVerified()) {
                    continue;
                }
                Optional<IntegrityAuditPlan.PlannedCheck> extractionCheck = findCheck(plan,
                        extraction.getArtifactId(), IntegrityCheckKind.EXTRACTED_CONTENT);
                if (!extractionCheck.isPresent()) {
                    continue;
                }
                ExtractionPreparer.PrepareResult prepared = preparer.prepare(componentIdentifier,
                        extractionCheck.get(), callback.getSourceArtifact(), source,
                        callback.getUnarchiveMethod() == null ? Unarchive.NONE.name()
                                : callback.getUnarchiveMethod().name(), callback.getExtractor());
                if (prepared.isUsable()) {
                    rePreparedAny = true;
                } else {
                    logger.atWarn().kv("component", componentIdentifier.toString())
                            .kv("artifactId", extraction.getArtifactId())
                            .kv("failureDetail", prepared.getFailureDetail() == null ? "UNKNOWN"
                                    : prepared.getFailureDetail().name())
                            .log("Failed to re-prepare extracted artifact; it remains unusable");
                }
            }

            return rePreparedAny ? executor.execute(planner.plan(componentIdentifier, recipe)) : report;
        }
    }

    /**
     * Revalidate a prior conclusion if the underlying object may have been replaced.
     *
     * <p>When the identity still matches the conclusion is reused. When it does not, the object is re-verified once and
     * the fresh result is returned; a caller must apply its policy to that result before use.</p>
     *
     * @param componentIdentifier component identity
     * @param artifactCheck       planned artifact-content check
     * @param verifiedIdentity    identity captured when the prior conclusion was produced
     * @return current result; never a stale {@code VERIFIED} for a replaced object
     */
    public IntegrityCheckResult revalidateIfReplaced(@NonNull ComponentIdentifier componentIdentifier,
                                                     @NonNull IntegrityAuditPlan.PlannedCheck artifactCheck,
                                                     @NonNull ArtifactIdentity verifiedIdentity) {
        Path path = artifactCheck.getExpectedPath();
        BasicFileAttributes current;
        try {
            current = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            IntegrityStatus status = Files.notExists(path, LinkOption.NOFOLLOW_LINKS)
                    ? IntegrityStatus.FILE_MISSING : IntegrityStatus.UNVERIFIABLE;
            IntegrityDetail detail = status == IntegrityStatus.FILE_MISSING
                    ? IntegrityDetail.NONE : IntegrityDetail.READ_ERROR;
            return IntegrityCheckResult.builder().componentIdentifier(componentIdentifier)
                    .artifactId(artifactCheck.getArtifactId()).expectedPath(path)
                    .relativePath(artifactCheck.getRelativePath()).checkKind(IntegrityCheckKind.ARTIFACT_CONTENT)
                    .status(status).detail(detail).message("artifact is no longer readable for revalidation").build();
        }
        if (verifiedIdentity.matches(current)) {
            return IntegrityCheckResult.builder().componentIdentifier(componentIdentifier)
                    .artifactId(artifactCheck.getArtifactId()).expectedPath(path)
                    .relativePath(artifactCheck.getRelativePath()).checkKind(IntegrityCheckKind.ARTIFACT_CONTENT)
                    .status(IntegrityStatus.VERIFIED).detail(IntegrityDetail.NONE)
                    .message("artifact unchanged since audit").build();
        }
        return executor.execute(IntegrityAuditPlan.builder().componentIdentifier(componentIdentifier)
                .checks(Collections.singletonList(artifactCheck)).build())
                .getArtifactResults().get(0);
    }

    /**
     * Verify the raw content of one artifact and return the conclusions the caller needs before use.
     *
     * <p>This is the hook a use path calls after it has ensured bytes are present and before it hands a path to a
     * lifecycle step. It never downloads; a caller that finds a failing result schedules repair itself.</p>
     *
     * @param componentIdentifier component identity
     * @param artifact            artifact from the recipe
     * @return per-check results for this artifact, in plan order
     * @throws IOException if a store path cannot be resolved
     */
    public List<IntegrityCheckResult> verifyArtifact(@NonNull ComponentIdentifier componentIdentifier,
                                                     @NonNull ComponentArtifact artifact) throws IOException {
        try (LockScope lock = LockScope.lock(lockFor(componentIdentifier))) {
            IntegrityAuditPlan plan = IntegrityAuditPlan.builder().componentIdentifier(componentIdentifier)
                    .checks(planner.planArtifact(componentIdentifier, artifact)).build();
            IntegrityAuditReport report = executor.execute(plan);
            List<IntegrityCheckResult> results = new ArrayList<>(report.getArtifactResults());
            results.addAll(report.getExtractionResults());
            return results;
        }
    }

    /**
     * Ensure a trustworthy extracted directory for an artifact, reusing an existing verified one and otherwise
     * preparing a fresh one through an isolated staging area.
     *
     * <p>An existing directory is only reused when both the source artifact and the extraction verify. Otherwise the
     * directory is re-prepared from the verified artifact. Artifacts that do not currently verify are refused
     * ({@link IntegrityDetail#SOURCE_UNVERIFIED}); the caller is expected to repair the download rather than unpack
     * unverified bytes.</p>
     *
     * @param componentIdentifier component identity
     * @param artifact            artifact from the recipe
     * @param unarchive           unarchive method
     * @param extractor           unpack implementation
     * @return preparation outcome; {@link ExtractionPreparer.PrepareResult#isUsable()} is true when a trustworthy
     *         directory now exists
     * @throws IOException if a store path cannot be resolved
     */
    public ExtractionPreparer.PrepareResult prepareVerifiedExtraction(
            @NonNull ComponentIdentifier componentIdentifier,
            @NonNull ComponentArtifact artifact,
            @NonNull Unarchive unarchive, @NonNull Extractor extractor) throws IOException {
        try (LockScope lock = LockScope.lock(lockFor(componentIdentifier))) {
            List<IntegrityAuditPlan.PlannedCheck> checks = planner.planArtifact(componentIdentifier, artifact);
            Optional<IntegrityAuditPlan.PlannedCheck> extractionCheck = checks.stream()
                    .filter(c -> c.getCheckKind() == IntegrityCheckKind.EXTRACTED_CONTENT).findFirst();
            if (!extractionCheck.isPresent()) {
                return ExtractionPreparer.PrepareResult.failure(IntegrityStatus.UNVERIFIABLE,
                        IntegrityDetail.SOURCE_UNVERIFIED, "artifact is not planned for extraction");
            }
            IntegrityAuditReport report = executor.execute(IntegrityAuditPlan.builder()
                    .componentIdentifier(componentIdentifier).checks(checks).build());
            IntegrityCheckResult source = report.getArtifactResults().isEmpty() ? null
                    : report.getArtifactResults().get(0);
            if (source == null) {
                return ExtractionPreparer.PrepareResult.failure(IntegrityStatus.UNVERIFIABLE,
                        IntegrityDetail.SOURCE_UNVERIFIED, "artifact content was not checked");
            }
            if (source.isVerified() && report.extractionVerified(extractionCheck.get().getArtifactId())) {
                // The existing directory already agrees with a verified source; nothing to redo.
                return ExtractionPreparer.PrepareResult.alreadyUsable();
            }
            return preparer.prepare(componentIdentifier, extractionCheck.get(),
                    extractionCheck.get().getExpectedPath(), source, unarchive.name(), extractor);
        }
    }

    /**
     * Collect every result for one artifact from a report.
     *
     * @param report report to inspect
     * @param artifactId artifact identity
     * @return every result for one artifact
     */
    public List<IntegrityCheckResult> resultsFor(IntegrityAuditReport report, String artifactId) {
        List<IntegrityCheckResult> results = report.getArtifactResults().stream()
                .filter(r -> r.getArtifactId().equals(artifactId)).collect(Collectors.toList());
        results.addAll(report.getExtractionResults().stream()
                .filter(r -> r.getArtifactId().equals(artifactId)).collect(Collectors.toList()));
        return results;
    }

    private static Optional<IntegrityAuditPlan.PlannedCheck> findCheck(IntegrityAuditPlan plan, String artifactId,
                                                                       IntegrityCheckKind kind) {
        return plan.getChecks().stream()
                .filter(c -> c.getCheckKind() == kind && c.getArtifactId().equals(artifactId)).findFirst();
    }

    private Lock lockFor(ComponentIdentifier componentIdentifier) {
        return componentLocks.computeIfAbsent(componentIdentifier.toString(),
                k -> LockFactory.newReentrantLock("artifact-integrity-" + k));
    }

    /**
     * Callbacks needed to re-prepare an extracted directory from a verified artifact. The source artifact must already
     * verify; the preparer refuses otherwise.
     */
    public interface RePreparation {
        Path getSourceArtifact();

        Extractor getExtractor();

        Unarchive getUnarchiveMethod();
    }

    /**
     * Convenience factory for a re-preparation callback.
     *
     * @param sourceArtifact verified artifact file
     * @param extractor      unpack implementation
     * @param unarchive      unarchive method
     * @return callback
     */
    public static RePreparation rePrepare(Path sourceArtifact, Extractor extractor, Unarchive unarchive) {
        return new RePreparation() {
            @Override
            public Path getSourceArtifact() {
                return sourceArtifact;
            }

            @Override
            public Extractor getExtractor() {
                return extractor;
            }

            @Override
            public Unarchive getUnarchiveMethod() {
                return unarchive;
            }
        };
    }

    /**
     * Guard used by callers that must not use an object the policy rejects.
     *
     * @param result policy decision source
     * @param policy active policy
     * @throws IntegrityCheckException when the policy does not allow use
     */
    public static void requireUsable(@NonNull IntegrityCheckResult result, @NonNull IntegrityPolicy policy)
            throws IntegrityCheckException {
        if (!policy.allows(result)) {
            throw new IntegrityCheckException(result.getMessage());
        }
    }
}

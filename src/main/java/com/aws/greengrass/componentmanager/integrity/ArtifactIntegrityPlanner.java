/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.amazon.aws.iot.greengrass.component.common.Unarchive;
import com.aws.greengrass.componentmanager.models.ComponentArtifact;
import com.aws.greengrass.componentmanager.models.ComponentIdentifier;
import com.aws.greengrass.componentmanager.models.ComponentRecipe;
import com.aws.greengrass.util.NucleusPaths;
import lombok.NonNull;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.inject.Inject;

/**
 * Builds an {@link IntegrityAuditPlan} from a recipe. It resolves the same on-disk locations that the download and
 * unpack code paths use, without instantiating a downloader or contacting the network.
 *
 * <p>The filename rules mirror {@code GreengrassRepositoryDownloader}, {@code S3Downloader} and the Docker downloader.
 * Docker artifacts are not materialized as files, so they produce no planned check.</p>
 */
public class ArtifactIntegrityPlanner {

    private static final String GREENGRASS_SCHEME = "GREENGRASS";
    private static final String S3_SCHEME = "S3";
    private static final String DOCKER_SCHEME = "DOCKER";

    private final NucleusPaths nucleusPaths;

    @Inject
    public ArtifactIntegrityPlanner(NucleusPaths nucleusPaths) {
        this.nucleusPaths = nucleusPaths;
    }

    /**
     * Build a plan for every artifact in the already platform-resolved recipe.
     *
     * @param componentIdentifier component identity
     * @param recipe              resolved recipe
     * @return plan, possibly empty when the component has no file artifacts
     * @throws IOException if a store path cannot be resolved
     */
    public IntegrityAuditPlan plan(@NonNull ComponentIdentifier componentIdentifier, @NonNull ComponentRecipe recipe)
            throws IOException {
        Path artifactDirectory = nucleusPaths.artifactPath(componentIdentifier);
        List<IntegrityAuditPlan.PlannedCheck> checks = new ArrayList<>();

        for (ComponentArtifact artifact : recipe.getArtifacts()) {
            String filename = resolveArtifactFilename(artifact.getArtifactUri());
            if (filename == null) {
                continue;
            }
            DigestSpec digestSpec = DigestSpec.parse(artifact.getAlgorithm(), artifact.getChecksum());
            Unarchive unarchive = artifact.getUnarchive() == null ? Unarchive.NONE : artifact.getUnarchive();
            boolean unarchived = !Unarchive.NONE.equals(unarchive);

            Path expectedArtifactPath = artifactDirectory.resolve(filename);
            if (unarchived) {
                Path extractionRoot = resolveExtractionRoot(componentIdentifier, filename);
                checks.add(IntegrityAuditPlan.PlannedCheck.builder().artifactId(filename)
                        .expectedPath(expectedArtifactPath).relativePath(filename)
                        .checkKind(IntegrityCheckKind.ARTIFACT_CONTENT).digestSpec(digestSpec).unarchived(true)
                        .extractionRoot(extractionRoot).build());
                checks.add(IntegrityAuditPlan.PlannedCheck.builder().artifactId(filename)
                        .expectedPath(extractionRoot).relativePath(stripExtension(filename))
                        .checkKind(IntegrityCheckKind.EXTRACTED_CONTENT).digestSpec(digestSpec).unarchived(true)
                        .extractionRoot(extractionRoot).build());
            } else {
                checks.add(IntegrityAuditPlan.PlannedCheck.builder().artifactId(filename)
                        .expectedPath(expectedArtifactPath).relativePath(filename)
                        .checkKind(IntegrityCheckKind.ARTIFACT_CONTENT).digestSpec(digestSpec).unarchived(false)
                        .build());
            }
        }
        return IntegrityAuditPlan.builder().componentIdentifier(componentIdentifier).checks(checks).build();
    }

    /**
     * Build the checks for a single artifact without requiring a full recipe.
     *
     * @param componentIdentifier component identity
     * @param artifact            artifact from the recipe
     * @return checks for this artifact, empty for a Docker artifact
     * @throws IOException if a store path cannot be resolved
     */
    public List<IntegrityAuditPlan.PlannedCheck> planArtifact(@NonNull ComponentIdentifier componentIdentifier,
                                                              @NonNull ComponentArtifact artifact) throws IOException {
        String filename = resolveArtifactFilename(artifact.getArtifactUri());
        if (filename == null) {
            return new ArrayList<>();
        }
        Path artifactDirectory = nucleusPaths.artifactPath(componentIdentifier);
        DigestSpec digestSpec = DigestSpec.parse(artifact.getAlgorithm(), artifact.getChecksum());
        Unarchive unarchive = artifact.getUnarchive() == null ? Unarchive.NONE : artifact.getUnarchive();
        boolean unarchived = !Unarchive.NONE.equals(unarchive);

        List<IntegrityAuditPlan.PlannedCheck> checks = new ArrayList<>();
        Path expectedArtifactPath = artifactDirectory.resolve(filename);
        if (unarchived) {
            Path extractionRoot = resolveExtractionRoot(componentIdentifier, filename);
            checks.add(IntegrityAuditPlan.PlannedCheck.builder().artifactId(filename)
                    .expectedPath(expectedArtifactPath).relativePath(filename)
                    .checkKind(IntegrityCheckKind.ARTIFACT_CONTENT).digestSpec(digestSpec).unarchived(true)
                    .extractionRoot(extractionRoot).build());
            checks.add(IntegrityAuditPlan.PlannedCheck.builder().artifactId(filename)
                    .expectedPath(extractionRoot).relativePath(stripExtension(filename))
                    .checkKind(IntegrityCheckKind.EXTRACTED_CONTENT).digestSpec(digestSpec).unarchived(true)
                    .extractionRoot(extractionRoot).build());
        } else {
            checks.add(IntegrityAuditPlan.PlannedCheck.builder().artifactId(filename)
                    .expectedPath(expectedArtifactPath).relativePath(filename)
                    .checkKind(IntegrityCheckKind.ARTIFACT_CONTENT).digestSpec(digestSpec).unarchived(false).build());
        }
        return checks;
    }

    /**
     * Resolve the artifact file name the same way the downloaders do.
     *
     * @param uri artifact URI
     * @return local file name, or null when the artifact has no file representation
     */
    public static String resolveArtifactFilename(URI uri) {
        if (uri == null || uri.getScheme() == null) {
            return null;
        }
        String scheme = uri.getScheme().toUpperCase(Locale.ROOT);
        if (DOCKER_SCHEME.equals(scheme)) {
            return null;
        }
        if (GREENGRASS_SCHEME.equals(scheme)) {
            return Objects.toString(Paths.get(uri.getSchemeSpecificPart()).getFileName(), null);
        }
        if (S3_SCHEME.equals(scheme)) {
            String[] parts = uri.getSchemeSpecificPart().split("/");
            return parts.length == 0 ? null : parts[parts.length - 1];
        }
        return null;
    }

    /**
     * Extraction root for an artifact, matching {@code NucleusPaths.unarchiveArtifactPath(id, name)} where name is the
     * artifact filename with its final extension removed.
     *
     * @param componentIdentifier component identity
     * @param filename            artifact file name
     * @return extraction root path
     * @throws IOException if the path cannot be resolved
     */
    public Path resolveExtractionRoot(ComponentIdentifier componentIdentifier, String filename) throws IOException {
        return nucleusPaths.unarchiveArtifactPath(componentIdentifier, stripExtension(filename));
    }

    static String stripExtension(String filename) {
        int dot = filename.indexOf('.');
        if (dot > 0) {
            return filename.substring(0, filename.lastIndexOf('.'));
        }
        return filename;
    }
}

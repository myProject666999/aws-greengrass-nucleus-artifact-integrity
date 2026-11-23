/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.aws.greengrass.componentmanager.integrity;

import com.aws.greengrass.util.Utils;
import lombok.Builder;
import lombok.Value;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Parsed and validated representation of the recipe artifact digest contract.
 *
 * <p>The contract is the one already used by {@code ArtifactDownloader}: the recipe supplies an {@code Algorithm}
 * name understood by {@link MessageDigest#getInstance(String)} and a {@code Digest} that is the standard Base64
 * encoding of the raw digest bytes. This class never invents a different encoding (for example hex) and never
 * narrows the set of algorithms beyond what the running JVM provides.</p>
 */
@Value
@Builder
public class DigestSpec {

    String algorithm;

    /**
     * Raw digest bytes decoded from the recipe Base64 checksum.
     */
    byte[] expectedDigestBytes;

    /**
     * Re-encoded canonical Base64 form of {@link #expectedDigestBytes}. Compared against the recipe string to detect
     * a legal-but-non-canonical encoding.
     */
    String canonicalChecksum;

    IntegrityStatus parseStatus;

    IntegrityDetail parseDetail;

    String parseMessage;

    public boolean usable() {
        return parseStatus == IntegrityStatus.VERIFIED;
    }

    /**
     * Validate recipe algorithm and checksum fields.
     *
     * @param algorithm declared algorithm, may be null or blank
     * @param checksum  declared Base64 checksum, may be null or blank
     * @return parsed spec; inspect {@link #usable()} before using the expected bytes
     */
    public static DigestSpec parse(String algorithm, String checksum) {
        boolean hasAlgorithm = Utils.isNotEmpty(algorithm);
        boolean hasChecksum = Utils.isNotEmpty(checksum);

        if (!hasAlgorithm && !hasChecksum) {
            // A local recipe without a digest is a documented, acceptable input. It is not corruption.
            return DigestSpec.builder().algorithm(null).parseStatus(IntegrityStatus.UNVERIFIABLE)
                    .parseDetail(IntegrityDetail.LEGACY_NO_DIGEST)
                    .parseMessage("no algorithm or checksum in recipe; content cannot be verified").build();
        }
        if (hasAlgorithm != hasChecksum) {
            return DigestSpec.builder().algorithm(algorithm).parseStatus(IntegrityStatus.METADATA_INCOMPLETE)
                    .parseDetail(IntegrityDetail.METADATA_PARTIAL)
                    .parseMessage("recipe declares only one of algorithm and checksum").build();
        }

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            return DigestSpec.builder().algorithm(algorithm).parseStatus(IntegrityStatus.ALGORITHM_UNSUPPORTED)
                    .parseDetail(IntegrityDetail.ALGORITHM_UNSUPPORTED)
                    .parseMessage("digest algorithm is not supported by the JVM").build();
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(checksum);
        } catch (IllegalArgumentException e) {
            return DigestSpec.builder().algorithm(algorithm).parseStatus(IntegrityStatus.METADATA_INCOMPLETE)
                    .parseDetail(IntegrityDetail.DIGEST_INVALID_BASE64)
                    .parseMessage("recipe checksum is not valid Base64").build();
        }

        int expectedLength = messageDigest.getDigestLength();
        if (decoded.length != expectedLength) {
            return DigestSpec.builder().algorithm(algorithm).parseStatus(IntegrityStatus.METADATA_INCOMPLETE)
                    .parseDetail(IntegrityDetail.DIGEST_LENGTH_MISMATCH)
                    .parseMessage(String.format("decoded checksum is %d bytes but algorithm produces %d",
                            decoded.length, expectedLength)).build();
        }

        String canonical = Base64.getEncoder().encodeToString(decoded);
        if (!canonical.equals(checksum)) {
            return DigestSpec.builder().algorithm(algorithm).expectedDigestBytes(decoded)
                    .canonicalChecksum(canonical).parseStatus(IntegrityStatus.METADATA_INCOMPLETE)
                    .parseDetail(IntegrityDetail.DIGEST_INVALID_BASE64)
                    .parseMessage("recipe checksum is valid Base64 but not in canonical padded form").build();
        }

        return DigestSpec.builder().algorithm(algorithm).expectedDigestBytes(decoded).canonicalChecksum(canonical)
                .parseStatus(IntegrityStatus.VERIFIED).parseDetail(IntegrityDetail.NONE).parseMessage(null).build();
    }

    /**
     * Constant-time comparison of a computed Base64 digest against the expected one.
     *
     * @param computedCanonicalBase64 Base64 produced by the read path
     * @return true when the encodings match
     */
    public boolean matches(String computedCanonicalBase64) {
        if (canonicalChecksum == null || computedCanonicalBase64 == null) {
            return false;
        }
        return MessageDigest.isEqual(canonicalChecksum.getBytes(StandardCharsets.US_ASCII),
                computedCanonicalBase64.getBytes(StandardCharsets.US_ASCII));
    }
}

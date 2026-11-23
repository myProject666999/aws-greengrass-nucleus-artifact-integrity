# Artifact Integrity Audit

This package adds an **offline, read-only integrity audit** for artifacts already on the device and for the result of
unpacking them. It does not download, does not delete, and does not change the existing download retry / resume path.

## What was already checked

`ArtifactDownloader` computes a `MessageDigest` while downloading and compares the Base64 encoding with the recipe
`checksum`. `downloadRequired()` also recomputes the digest of an existing artifact that has digest metadata and skips
the download only when it matches. So there has never been "no verification at all". This package does not claim
otherwise; it adds checks at the moments those paths do not cover, and makes the results explicit and testable.

## What this package checks

1. **Raw artifact content** (`ARTIFACT_CONTENT`) against the recipe `algorithm` + Base64 `checksum`.
2. **Unpacked result** (`EXTRACTED_CONTENT`) against a provenance record created when the directory was produced.

### Digest contract

- Same contract as `ArtifactDownloader`: `algorithm` is a JCA `MessageDigest` name, `checksum` is the **standard Base64**
  encoding of the raw digest bytes. No hex, no re-encoding.
- The set of supported algorithms is whatever the running JVM provides; nothing is narrowed here.
- `algorithm` and `checksum` must be supplied together. Only one is `METADATA_INCOMPLETE` / `METADATA_PARTIAL`.
- Invalid Base64 (`DIGEST_INVALID_BASE64`), decoded length that does not match the algorithm
  (`DIGEST_LENGTH_MISMATCH`) and stable content that differs (`CONTENT_MISMATCH`) are reported separately.
- A local recipe with **no** digest is accepted and reported as `UNVERIFIABLE` / `LEGACY_NO_DIGEST`. It is never
  reported as corruption.

### Status values

| Status | Meaning |
| --- | --- |
| `VERIFIED` | checked and consistent |
| `FILE_MISSING` | expected file/directory/member absent |
| `FILE_CORRUPTED` | exist and differs (content mismatch, modified/missing/extra member, symlink) |
| `METADATA_INCOMPLETE` | recipe digest missing a half, malformed or wrong length |
| `ALGORITHM_UNSUPPORTED` | JVM cannot provide the algorithm |
| `UNVERIFIABLE` | no trustworthy conclusion: legacy metadata, absent provenance, read error, changed during read |

`VERIFIED` is only returned when a check actually ran and matched. "No failure observed" is not `VERIFIED`.

### Read failures vs. mismatch

A read that fails (`READ_ERROR`), a read that changes while in progress (`CHANGED_DURING_READ`), a short read
(`TRUNCATED_READ`) and a stable content mismatch (`CONTENT_MISMATCH`) are distinct. File size or modification time are
used only to detect change during the read; they never allow skipping the content check.

## Extraction trust model

A verified archive digest does **not** imply the directory unpacked from it is still intact. Trust comes from a
provenance record (`ArtifactExtractionRecord`) written when the directory was produced from a **verified** artifact:

- The record lives under `{componentStore}/integrity/...`, **outside** the extraction root, so it is never mistaken for
  an extra extracted member.
- A directory with **no** record (legacy) is `UNVERIFIABLE` / `RECORD_MISSING`; it is not blessed by a one-time disk
  scan.
- A record whose source was not verified, or whose recipe digest no longer matches, is `UNVERIFIABLE`.
- Member scope: every file is hashed (SHA-256) and every directory is listed. Missing, modified and extra members and
  symlinks are reported. Paths in `excludedRuntimePaths` are ignored so legitimate runtime output in a work directory
  is not counted as pollution.

### Re-preparation

`ExtractionPreparer` unpacks into an isolated `.staging-*` sibling directory, hashes every member, then publishes with a
same-directory rename while keeping the previous result as a `.backup-*`. If anything fails, the previous directory is
restored and no half directory is left where a lifecycle step could pick it up.

- Preparation refuses a source that is not verified (`SOURCE_UNVERIFIED`).
- If persisting the record fails after publish, the directory is rolled back.
- Cross-platform note: the rename is same-directory. Where a filesystem cannot rename atomically the code falls back to
  a plain move. That is not universally atomic; a move that cannot complete (for example a file held open by another
  process) is reported as a failure, not a success.

## Boundary and concurrency

`ArtifactIntegrityManager` is the pre-use boundary. It serializes audit, re-preparation and (by the caller) cleanup per
component with an in-process lock. A conclusion is bound to the `ArtifactIdentity` of the object inspected;
`revalidateIfReplaced` re-verifies once or refuses when the object was replaced, instead of reusing a stale
`VERIFIED`.

## Policy

- `REQUIRE_VERIFIED` (default intent): only `VERIFIED` objects may be used.
- `ALLOW_UNVERIFIED`: explicit compatibility switch that lets `UNVERIFIABLE` (legacy) objects through but still blocks
  proven corruption.

Callers decide whether a failed audit leads to repair. The auditor never deletes or downloads on its own.

## Migration

- **Historical artifacts without a digest**: reported `UNVERIFIABLE`; the existing in-place unpack path is unchanged
  and no provenance is recorded. Under `REQUIRE_VERIFIED` they are not used; under `ALLOW_UNVERIFIED` they are.
- **Old unpacked directories without a record**: `UNVERIFIABLE`; they are re-prepared from a verified artifact when one
  exists, otherwise they stay unusable unless the explicit compatibility policy allows them.
- **Read-only directories**: reported as read errors / publish failures, never as verified.

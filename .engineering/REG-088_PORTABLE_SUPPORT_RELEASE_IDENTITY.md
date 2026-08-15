# REG-088 — Portable Support Release Identity

Status: **LOCKED**

## Defect

The privacy-safe Support Bundle identified a directly launched portable package as `version: "unknown"` and `release: "development"`. The route depended on npm process environment metadata (`npm_package_version`) and an optional `EMAIL_SHIELD_RELEASE_ID`, but the shipped launcher executes the bundled Node runtime directly rather than through npm and does not have a trustworthy release-ID environment value.

The package itself already contains the canonical `release-manifest.json` with the product version, exact Git commit, platform, architecture, Node runtime and release ID. Reporting development metadata from that same verified package weakened support diagnostics and could make two release artifacts unnecessarily difficult to distinguish during incident handling.

## Root repair

Consumer support identity is now resolved from the package-root `release-manifest.json` whenever the running executable is the bundled `runtime/node` or `runtime/node.exe`. The manifest is read through Email Shield's existing descriptor-bound, bounded, no-follow local-file integrity primitive and is accepted only when its product/schema/version/release ID/commit/platform/architecture/runtime/entrypoint identity is structurally consistent with the running package.

A bundled runtime with missing, malformed, mismatched or oversized metadata reports `unknown / unverified_portable`; it never falls back to the misleading `development` label. Genuine source/developer execution retains the existing npm/environment fallback.

This changes only diagnostic identity. No mailbox content, account identity, credential, token, URL, Family private data or device key is added to the Support Bundle.

## Permanent protection

- `tests/unit/runtimeReleaseIdentity.test.ts` locks valid packaged identity, fail-honest malformed metadata and source-development fallback.
- Consumer Support Bundle uses this one resolver rather than reading npm-only release metadata directly.
- The portable package verification and post-publication manifest integrity gates continue to bind the exact shipped release files.
- Final consumer qualification must verify that a downloaded portable package's Support Bundle version/release exactly match its own canonical release manifest.

Any future packaged build that labels itself `development`/`unknown` despite a valid canonical portable manifest is a blocking support/release-diagnostics regression.
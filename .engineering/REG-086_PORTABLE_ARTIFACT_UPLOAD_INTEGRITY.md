# REG-086 — Portable Artifact Upload Integrity

Status: **LOCKED**

## Defect

The Engineering Gate verified the generated portable package directory and its canonical SHA-256 inventory before publication, but the subsequent `actions/upload-artifact` step used its default hidden-file behavior. Hidden files inside packaged production dependencies were therefore omitted from the published GitHub Actions artifact even though they were present when `package:verify` succeeded.

The result was a release artifact that was no longer byte-for-byte equivalent to the verified package: its `release-manifest.json` listed files that the downloaded artifact did not contain. A green source/package gate could therefore publish an artifact that failed its own canonical inventory.

## Root repair

The portable-package upload step now explicitly sets `include-hidden-files: true`. Publication therefore preserves dotfiles that are already part of the gate-approved production dependency closure and canonical release manifest instead of silently filtering them after verification.

This does not broaden the package source set: `build-portable.mjs` and `verify-portable.mjs` retain the existing lockfile production-closure, symlink, secret/dev-file, size, runtime and SHA-256 inventory boundaries. It only makes the uploaded artifact faithfully preserve the package that those controls already approved.

## Permanent protection

- `tests/unit/portablePackagingArchitecture.test.ts` requires the verified portable upload step to retain `include-hidden-files: true`.
- The full Windows/macOS/Ubuntu Engineering Gate continues to build and verify each host-targeted portable package before upload.
- Release qualification must verify a freshly downloaded artifact against its embedded canonical manifest; pre-upload verification alone is not sufficient release evidence.

Any future workflow change that allows artifact publication to drop manifest-listed files is a blocking release-integrity regression.

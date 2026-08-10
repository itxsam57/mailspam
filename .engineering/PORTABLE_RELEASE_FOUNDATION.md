# Email Shield — Portable Release Foundation

Date: 2026-08-11
Status: Milestone 2 portable packaging foundation implemented; signed installers, archives, update/rollback and platform acceptance remain Milestone 3/external work.

## Artifact contract

`npm run package:verify` builds and verifies one host-targeted directory under `artifacts/release/`:

```text
email-shield-<version>-<platform>-<architecture>/
  EmailShield.cmd or email-shield
  release-manifest.json
  runtime/node.exe or runtime/node
  app/server/dist/
  app/server/package.json
  app/web/
  app/node_modules/
  app/package-lock.json
```

The package embeds the exact Node 22 runtime executing the build, the completed TypeScript production output, browser assets and only non-dev/non-workspace dependency packages from lockfile v3. Nested `node_modules` trees are reconstructed one declared production package at a time so recursive copying cannot smuggle dev-only dependencies into the artifact.

The runtime depends on Google’s Gmail-specific `@googleapis/gmail` client plus `google-auth-library`, not the broad generated `googleapis` catalog. This keeps the package scoped to the one Google API Email Shield actually uses while preserving the official OAuth and Gmail client implementations.

Package construction performs no network download. The Windows Engineering Gate therefore packages the setup-node Windows runtime, macOS packages its macOS runtime, and Linux packages its Linux runtime. Each artifact is platform/architecture specific; no build claims cross-compilation.

## Reproducibility and integrity

- Release packaging requires a clean git worktree; the explicit dirty override exists only for local development tests.
- Package paths are derived from validated product version, platform and architecture values and may be replaced only beneath the exact generated release directory.
- Source symlinks and non-regular files are rejected.
- File modes normalize to `0644` or `0755`; mtimes normalize to `2000-01-01T00:00:00Z`.
- The sorted manifest records every non-manifest file’s relative path, byte length, SHA-256 and normalized mode.
- The complete non-manifest artifact is limited to 256 MiB; its summed byte count is verified and bound into the manifest so dependency/runtime growth fails the release gate instead of silently bloating distribution.
- A canonical manifest payload binds version, exact 40-character git commit, platform, architecture, Node version, entrypoint, launcher, total artifact bytes, production-package list and file inventory into one SHA-256 release ID.
- Verification recomputes the canonical release ID and complete inventory, rejects extra/missing/changed files, rejects state/secret filenames and dev dependency directories, executes the bundled runtime version check and starts the bundled desktop entrypoint on an isolated loopback port.

## CI evidence

The unchanged Engineering Gate includes `package:verify` after both compiled service smokes. GitHub Actions runs it on Windows, macOS and Ubuntu and uploads the verified host-targeted directory separately from engineering reports.

## Honest boundary

This is a portable package, not an installed or signed product. It does not claim Authenticode, Apple Developer ID/notarization, MSI/PKG/DMG, Start Menu/Dock integration, automatic updates, rollback, uninstall cleanup or mobile application delivery. Those remain canonical Milestone 3 requirements, and signing/notarization/store acceptance requires owner identities and external platform services.

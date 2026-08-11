# Email Shield — Signed Release, Update, Rollback and Uninstall Lifecycle

Date: 2026-08-11
Status: repository lifecycle implemented; production code-signing identities and native notarized installer acceptance remain external.

## Trust boundary

The portable package manifest authenticates every packaged byte with a canonical SHA-256 inventory and release ID. A separate exact-schema version-1 update envelope binds that release ID, complete portable-manifest digest, version, commit, platform, architecture, stable channel and minimum updater schema under an Ed25519 signature.

The install trust store is pinned during first installation and accepts one to four exact Ed25519 public keys for controlled overlap. It contains no private key. An update cannot replace its own trust root. Production signing requires an owner-controlled, owner-only private-key file and may optionally require an expected key ID so the wrong release identity fails before output.

The repository and Engineering Gate generate ephemeral test keys only to prove the real signing and packaged installer code paths. Those tests do not claim a production signing ceremony, Authenticode, Apple Developer ID, notarization or app-store approval.

## Lifecycle

1. `npm run package:verify` builds and verifies the exact host-targeted portable package.
2. `npm run release:trust -- <current-public.pem> [next-public.pem] --output <release-trust.json>` creates a strict pinned public trust store.
3. `EMAIL_SHIELD_RELEASE_SIGNING_KEY_FILE=<owner-only-private.pem> npm run release:sign` rebuilds, executes the reviewed provider-compatibility contract and approved anonymized Regression Vault, rebuilds/verifies the exact clean-head portable package, then signs its manifest only if every stage passes. `EMAIL_SHIELD_RELEASE_SIGNING_KEY_ID` may pin the expected signer and `EMAIL_SHIELD_SIGNED_UPDATE_OUTPUT` may select an explicit output.
4. The packaged `tools/release-cli.mjs verify` verifies the envelope signature, signed target identity, portable-manifest digest and every package byte before installation.
5. `install` copies only a verified regular-file tree into a release-ID version slot, verifies it again after staging, stores the signed envelope separately, installs a stable host launcher and atomically activates the release.
6. `update` trusts only the installed pinned key set, requires the same platform/architecture and a strictly newer version, repeats staging verification, and retains the prior verified release as the rollback target.
7. `rollback` can activate only the recorded previous release after re-verifying its stored signed envelope and complete installed inventory. Arbitrary downgrades are rejected.
8. A torn activation fails closed when state and the launcher pointer differ. `repair` restores the pointer only after verifying the signed installed release again.
9. `uninstall` requires the exact managed-install marker. It preserves user data by default. Explicit data purge requires a separate exact managed-data marker, a non-root/non-home path independent from the install tree, and a directory containing only known Email Shield state names.

## Security properties

- Unknown fields, schema drift, non-canonical signatures, untrusted keys, target mismatch, symlinks, changed/extra/missing package bytes and manifest disagreement fail closed.
- Update cannot silently install the same or an older semantic version; downgrade exists only through the verified one-step rollback record.
- Fresh installation is transactional: a failed install removes only the newly created explicit install root.
- Program files and local state remain separate, so an ordinary uninstall never destroys policies or history.
- Release signing private keys are never copied into artifacts, packages, logs, command output or trust stores.

## External acceptance still required

- provision and protect the production Ed25519 release identity;
- wrap the verified host artifact in the chosen Windows/macOS native installer format;
- apply Authenticode/Developer ID signatures and Apple notarization;
- publish immutable release bundles through production distribution infrastructure;
- execute signed upgrade, rollback and uninstall acceptance on owned Windows/macOS systems;
- complete Android/iOS store signing and review when native shells exist.

These items require external identities or production platform infrastructure and must not be marked passed by ephemeral-key tests.

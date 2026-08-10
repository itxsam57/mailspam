# Dependency security closure

## Milestone 2 accepted baseline

The final Milestone 2 dependency audit identified repository-wide critical/high advisories in the Vitest/Vite/Nanoid development chain and moderate advisories in Microsoft/Google production dependency chains.

The reviewed remediation upgrades are:

- `vitest` `^4.1.10`
- `@azure/msal-node` `^5.5.0`
- `googleapis` `^174.0.1`

The generated npm lockfile is authoritative; it must not be hand-edited to make advisory output appear cleaner.

## Compatibility requirements

Dependency remediation is accepted only if all of these remain green:

1. strict source + test TypeScript typecheck;
2. production build;
3. Microsoft OAuth security, public-client compatibility, token-rotation, vault-custody and disconnect regressions;
4. Gmail OAuth security, Google compatibility and revocation regressions;
5. credential-vault and secured app-password session regressions;
6. the complete unit/integration corpus, Worker runtime, browser checks and compiled server/community smoke tests;
7. all three supported desktop Engineering Gate platforms;
8. the all-installed dependency inventory and blocking production audit.

## Current result

Engineering Gate 446 on the reviewed dependency-only implementation reported zero installed advisories across production and development dependencies.

## Non-goals

This does not promise that future package advisories cannot be published. Future advisories are new evidence and must be evaluated against the same gate rather than hidden, ignored or mass-fixed with an unreviewed force upgrade.

# Email Shield Engineering Automation

This directory installs the project-specific controls required by the AI Engineering Automation Kit without redesigning Email Shield.

## One-command gate

```bash
npm ci
npm run gate
```

`npm run verify` is kept as a compatibility alias for the same full gate.

The gate runs every applicable command-line check, continues long enough to capture all stage results, and writes:

```text
artifacts/engineering/verification-report.json
artifacts/engineering/VERIFICATION_REPORT.md
artifacts/engineering/MANUAL_TEST_HANDOFF.md
```

The artifact directory is generated and ignored locally. GitHub Actions uploads it for every Windows and Ubuntu run, even when the gate fails.

## Documents

- `PROJECT_PROFILE.md` — Section 00 repository audit and exact commands.
- `TEST_MATRIX.md` — automated versus owner-visible test ownership.
- `REGRESSION_REGISTER.md` — locked historical failures, known gaps and manual acceptance items.
- `MANUAL_TEST_HANDOFF_TEMPLATE.md` — source-controlled visible-browser checklist template.

## Gate behavior

- No production code is rewritten by the gate.
- No mailbox is connected and no real mailbox is modified in CI.
- Fixture adapters exercise the same canonical engine/API paths.
- Browser automation is limited to source/wiring validation and localhost API/SSE smoke. Subjective visible acceptance remains with the owner.
- A failed stage is recorded honestly; later independent stages still run when possible so the report is complete.
- Known product gaps remain visible in the regression register and are never converted into passing checks.

## Dependency audit switch

The full local gate enables the production dependency audit by default. Set this only for an intentionally offline diagnostic run:

```bash
ENGINEERING_AUDIT=0 npm run gate
```

GitHub Actions enables the audit on Ubuntu. Windows runs the same functional gate without duplicating the network audit.

## Future changes

A new architecture requires a profile and matrix update. Examples include adding a database, deployment target, UI framework, native client, queue, container, new provider or destructive mailbox action. Install only the checks that become applicable; do not copy unrelated automation into this repository.
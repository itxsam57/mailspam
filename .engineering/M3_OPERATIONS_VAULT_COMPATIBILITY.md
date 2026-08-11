# Milestone 3 Operations, Regression Vault and Provider Compatibility

Date: 2026-08-11  
Status: repository implementation and release gates complete; live-provider and deployed-service acceptance remain external.

## Privacy-safe operational dashboard

The protected desktop endpoint `GET /api/operations/v1/snapshot` returns exact schema version 1 and is reachable only with the process-local HttpOnly session plus CSRF proof. It is rate-limited and `no-store`. The visible dashboard renders only fixed-cardinality aggregates:

- attempts, success, failure, cancellation, active count and cumulative duration for the six canonical adapter operations;
- started/completed/failed/stopped scans and verdict counters for each of the five fixed providers;
- explicit message-level Safe approvals as false-positive review outcomes;
- accepted/failed privacy-reduced scam reports as abuse-review outcomes;
- verified-feed entry/pending-report counts, bounded destination-analysis telemetry and scheduled-background aggregate state.

The metrics API has no parameter for a mailbox label, address, account ID, message ID, sender, subject, body, destination, indicator, action token, exception or stack. Provider and operation labels are closed TypeScript unions. Adapter exception text is discarded after its fixed outcome counter is updated. Community-service Prometheus metrics remain the deployed aggregate feed/abuse surface described in `COMMUNITY_OPERATIONAL_METRICS.md`.

## Versioned provider compatibility

`fixtures/provider-compatibility/v1/capabilities.json` is the reviewed release contract for Gmail, iCloud, Outlook, Yahoo and generic IMAP. Authentication and transport may differ; all providers must expose connect, folder discovery, bounded page fetch, Quick/Full/Spam scans, cancellation, Trash, Spam/Junk reporting, canonical MIME and the shared portable core.

`npm run check:provider-compatibility` compares the compiled contract byte-for-byte with the versioned JSON and then executes connect, folder discovery, bounded canonical fetch, Spam/Junk, Trash, disconnect and pre-aborted cancellation through every provider fixture. Any capability removal or unreviewed schema drift blocks release.

This does not replace live provider acceptance. Gmail publication and controlled Outlook owner acceptance remain GAP-001/GAP-002.

## Reviewed anonymized Regression Vault

Original messages are never copied into the repository. Intake writes only a sanitized candidate under `EMAIL_SHIELD_DATA_DIR/regression-vault-intake` (or an explicit candidate root):

```text
npm run vault -- intake --file sample.eml --category credential_phishing --kind malicious --expected non_safe --authentication-trust unknown --attest-no-private-content
```

Sanitizer v1 removes routing and threading headers, replaces envelope identities, masks direct email/phone/IP values and rewrites HTTP(S) destinations to the reserved `unsafe.example` host while retaining path/form/urgency structure. Input is a non-symbolic regular file capped at 512 KiB. The operator attestation is mandatory because software cannot reliably identify every personal name in free-form prose.

Approval is a separate exact-digest decision:

```text
npm run vault -- approve --candidate-id <32-hex-id> --review-digest <64-hex-sha256> --reviewer-role security_reviewer
```

Approval re-reads and revalidates the sanitized bytes, requires the displayed SHA-256, accepts only fixed reviewer roles, scans the candidate through all five adapters, enforces Safe for legitimate controls or non-Safe for malicious samples, rejects duplicate IDs/digests, writes a placeholder-only sample, and atomically replaces the sorted strict manifest. The candidate remains outside source control for audit/re-review; it contains no original message.

`npm run check:regression-vault` revalidates manifest schema/provenance/sorting/deduplication, path containment, placeholder-only privacy rules, every sample SHA-256 and all five provider outcomes. It runs after the production build in the full Engineering Gate. `npm run release:sign` independently rebuilds, reruns provider compatibility plus the Regression Vault, and rebuilds/verifies the exact clean-head portable artifact before it will invoke the signing command, so a direct release-signing workflow cannot bypass these release gates or sign a stale package.

## Evidence and limitations

- Automated: `providerCompatibility.test.ts`, `localOperationalMetrics.test.ts`, `regressionVault.test.ts`, `localApiSecurity.test.ts`, browser source checks, the two compiled contract commands, corpus/Worker tests and full Engineering Gate.
- Manual: visible operations-table readability is part of owner accessibility/zoom acceptance.
- External: deployed alert thresholds/on-call integration, real provider smoke, Gmail publication, Outlook acceptance, production community monitoring/gateway controls and signed native distribution remain explicitly outside a repository-only pass.

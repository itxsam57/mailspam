# Governor live findings — 2026-08-25

## GOV-DETECT-001 — recipient address misread as sender/domain identity claim

**Live reproduction:** Real Gmail Quick Scan classified three legitimate Google security-alert messages as Review, score 4, with `EXPLICIT_DOMAIN_CLAIM_MISMATCH`. Subject form: `Security alert for webrefreshlab@gmail.com`; sender: `no-reply@accounts.google.com`.

**Root cause:** `server/src/engine/layers/identityImpersonation.ts` extracts explicit domains from the subject. `explicitDomains()` accepts any dotted token preceded by `@` as an asserted domain. Therefore the recipient address in the subject contributes `gmail.com` to `claimedDomains`; the subsequent comparison sees `google.com` vs `gmail.com` and creates a false mismatch. A recipient mailbox mention is not an organizational sender claim.

**RED contract:** `tests/unit/governorLiveDetectionRegression.test.ts` asserts that a recipient address in the subject must not create `EXPLICIT_DOMAIN_CLAIM_MISMATCH` solely from the recipient domain.

**Repair status:** Not repaired. Keep RED until batch-fix phase.

## GOV-SCAN-OBS-001 — fresh Governor fixtures absent from pasted Quick Scan result

Four controlled `[ESHIELD-GOV]` messages were independently confirmed as the newest Inbox messages through Gmail, but the owner-pasted 20-message Quick Scan result did not contain them and instead showed older messages. The Gmail adapter and `quickScan()` workflow are specified to request the Inbox first page with a 20-message limit for Gmail, and a fresh scan does not intentionally pass a resume cursor.

This is not yet classified as a product defect because live request/network evidence from the local process is still required to distinguish provider-fetch selection from stale browser presentation (#131 family). The self-hosted Windows Governor harness must capture the scan ID, start event, progress subjects for prefixed test fixtures, and browser rendering before assigning root cause.

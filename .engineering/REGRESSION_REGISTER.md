# Email Shield — Regression Register

Status values:

- **PRE-EXISTING-FIXED** — defect existed before the automation installation, was exposed by the stronger gate and corrected without deleting its history.
- **LOCKED** — fixed behavior with automated regression coverage; future failure blocks the gate.
- **LIVE-PASS** — verified against a controlled real mailbox and backed by automation where possible.
- **KNOWN-GAP** — acknowledged incomplete product capability; not misreported as a passing feature.
- **MANUAL** — requires final visible owner acceptance after automation passes.

## Pre-existing findings exposed during installation

| ID | Status | Finding | Resolution / protection |
|---|---|---|---|
| PRE-001 | PRE-EXISTING-FIXED | `tests/unit/messageIntentProfileLure.test.ts` constructed a `CanonicalEnvelope` without the required `diagnostics.contentCoverage` field. The former `build + Vitest` command compiled production source only and did not typecheck test sources, so the drift remained hidden while runtime tests passed. | Added `contentCoverage: "complete"` to the existing fixture and installed strict source-plus-test typechecking as a blocking Windows/Ubuntu gate. No production runtime failure was observed. |

## Locked regressions

| ID | Status | Regression / required invariant | Automated protection |
|---|---|---|---|
| REG-001 | LOCKED | SSE request lifecycle must not cancel a scan merely because the request completed; scan startup/errors remain visible. | `architectureRegression.test.ts`, API smoke |
| REG-002 | LOCKED | Compiled Worker must start on Windows and Ubuntu without TypeScript runtime loaders. | `scanWorkerRuntime.test.ts`, CI matrix |
| REG-003 | LOCKED | Partial messages with evidence remain Review/High Risk; unavailable content cannot silently become Safe. | `verdict.test.ts`, scan workflow tests |
| REG-004 | LOCKED | IMAP scans fetch bounded readable MIME parts and do not download raw messages or attachment bodies. | MIME/architecture regressions |
| REG-005 | LOCKED | Diagnostics expose privacy-reduced metadata only; no body, HTML, credential or raw unsubscribe target. | diagnostics/UI architecture tests, web check |
| REG-006 | LIVE-PASS | One-message Trash shows success only after provider confirms exactly one reversible move. | block/cleanup tests, UI architecture test, prior live iCloud pass |
| REG-007 | LOCKED | Block sender/domain is scoped to the selected connected account and never moves mail. | session policy tests, architecture tests |
| REG-008 | LOCKED | IMAP timeouts identify the exact stage, retry only before visible progress and force-close stalled sockets. | timeout/retry tests |
| REG-009 | LIVE-PASS | Personal policies survive restart/reconnection, remain account isolated and are encrypted at rest. | persistence/session tests, prior live restart pass |
| REG-010 | LOCKED | RFC 8058 unsubscribe uses opaque account tokens, exact form body, pinned public address and no redirect following. | unsubscribe/security tests |
| REG-011 | LOCKED | INBOX/special-use folder discovery, broad unsubscribe methods and bounded-content verdicts remain provider neutral. | folder, unsubscribe and inbox-classification tests |
| REG-012 | LOCKED | Authenticated official/private-relay mail avoids false Unknown while unrelated/shared-mail identities remain untrusted. | official identity tests |
| REG-013 | LOCKED | Safe mail stays outside warning cards, appears in a privacy-reduced audit and repeated link evidence is bounded. | Safe audit/link evidence tests |
| REG-014 | LOCKED | Local detection must not regress to a mailbox-specific compiled brand/domain list. | generalized identity architecture tests |
| REG-015 | LOCKED | Mark Safe is exact-message only; Trust sender is exact-address/account scoped; personal block and signed confirmed threat remain higher precedence. | provider-neutral review tests, verdict tests |
| REG-016 | LOCKED | Gmail, iCloud, Outlook, Yahoo and generic IMAP fixtures must use the same canonical scan/action contract. | corpus and provider-neutral tests |
| REG-017 | LOCKED | Stop must return control without freezing the UI server, and a new scan must be possible afterward. | worker tests; final visible handoff |
| REG-018 | LOCKED | Browser scripts, dynamic dependencies, DOM IDs and API action endpoints must remain syntactically and structurally connected. | `check:web` |
| REG-019 | LOCKED | Compiled server must start on localhost and complete fixture connection plus quick-scan SSE. | `smoke:server` |
| REG-020 | LOCKED | One command must create a complete engineering result and owner browser handoff even when a step fails. | `run-gate.mjs`, CI artifact upload |

## Known gaps — not accepted as complete

| ID | Status | Gap | Current boundary |
|---|---|---|---|
| GAP-001 | KNOWN-GAP | Guided Gmail OAuth onboarding | Adapter supports credentials; normal browser onboarding is not exposed or live-validated. |
| GAP-002 | KNOWN-GAP | Guided Outlook OAuth onboarding | Adapter supports credentials; normal browser onboarding is not exposed or live-validated. |
| GAP-003 | KNOWN-GAP | OS keychain-backed policy encryption key | Local AES-GCM file/key protection exists; keychain integration is not implemented. |
| GAP-004 | KNOWN-GAP | Production signed identity/threat-feed publisher, rotation and rollback | Runtime verification interfaces exist; publisher/distribution service is absent. |
| GAP-005 | KNOWN-GAP | Controlled real-destination Analyze Links validation | Hardened workflow exists; complete controlled live-URL validation remains. |
| GAP-006 | KNOWN-GAP | Production QR decoder | Injectable interface exists; production decoder is absent. |
| GAP-007 | KNOWN-GAP | Local API authentication and CSRF protection | Server binds to localhost; production web exposure is not approved. |
| GAP-008 | KNOWN-GAP | Community reporting aggregation | Milestone 2 scope. |
| GAP-009 | KNOWN-GAP | Editable policy-management centre and unblock/untrust/revoke UI | Policy storage/actions exist; complete management UI remains. |
| GAP-010 | KNOWN-GAP | Persisted resumable scan cursors and automatic continuation across restart/rate limits | Current worker retry is bounded to one early transient failure. |
| GAP-011 | KNOWN-GAP | Full mailbox-derived relationship history | Canonical relationship signals exist but production history depth is incomplete. |

## Manual visible acceptance register

| ID | Status | Visible requirement |
|---|---|---|
| MAN-001 | MANUAL | Dashboard loads without blank page, flicker, frozen controls or console-visible failure. |
| MAN-002 | MANUAL | Desktop and narrow/mobile layouts remain readable and controls do not overlap. |
| MAN-003 | MANUAL | All five fixture providers can be selected and visibly complete Quick scans. |
| MAN-004 | MANUAL | Full and Spam/Junk fixture scans show bounded progress and Stop remains responsive. |
| MAN-005 | MANUAL | Safe audit is understandable and shows only available actions. |
| MAN-006 | MANUAL | Review/High Risk/Unknown cards show correct confirmations and visible success/error feedback. |
| MAN-007 | MANUAL | Account switching does not visually leak actions or results between connected accounts. |
| MAN-008 | MANUAL | Controlled live iCloud scan remains responsive and credentials are not displayed after connection. |

## Register maintenance rule

Every fixed production defect must receive a new `REG-*` entry and an automated test before closure. Every pre-existing installation finding must remain a `PRE-*` item after correction. Every incomplete capability must remain a `GAP-*` item until implementation, automated verification and owner-visible acceptance are all complete. Do not delete history to make the register appear green.
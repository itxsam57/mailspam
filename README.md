# Email Shield — Local Detection and Shared Community Protection

Email Shield is a local-first, deterministic email scam-detection layer. Mailbox scans and message content remain on the user's machine. When the user explicitly selects **Report Scam to Email Shield**, the client may send a privacy-reduced indicator report to a configured community service; it never uploads the message body, subject, mailbox address, contacts, credentials, provider message ID, raw private URL path/query values, attachment names, or attachment content.

Milestone 1 is closed. Milestone 2 is **code-complete to its audited and automated boundary** but awaits registered owner/live/deployment acceptance. Milestone 3 repository work now includes signed release lifecycle, bounded background protection, portable core, accessibility/localization foundation, aggregate operations, Regression Vault, provider contracts and executable capacity/public-security documentation; actual Android/iOS mailbox shells remain missing and external/native acceptance remains open. See `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md`.

## Run the desktop client

```bash
npm ci
npm run gate
npm run dev
```

Open `http://127.0.0.1:4173`. Fixture mode loads the synthetic scam corpus without credentials. Live mode connects directly from the user's computer to the selected provider.

## Providers and live onboarding

One canonical envelope, detection pipeline, review workflow and community-report contract are shared by Gmail, iCloud, Outlook, Yahoo and Generic IMAP.

- **Gmail:** guided Authorization Code + PKCE desktop OAuth with loopback callback, stable Google identity, protected refresh-token custody, disconnect revocation and reconnect support.
- **Outlook:** guided Microsoft public-client Authorization Code + PKCE desktop OAuth with dynamic localhost callback, stable Graph identity, protected refresh-token rotation/custody and reconnect support. No client secret is required by the guided Outlook flow.
- **iCloud / Yahoo:** email address plus provider-approved app-specific password.
- **Generic IMAP:** TLS host/port, username and app password.

The live provider adapters use the same scan/action contract; real owner acceptance remains registered separately where credentials or external infrastructure are required.

## Local desktop security

The desktop API is loopback-only and protected by:

- process-local HttpOnly session authentication;
- protected reads and scan-stream handshakes;
- CSRF/same-origin enforcement;
- one-time mutation nonces and replay rejection;
- Host/forwarded-header and DNS-rebinding defenses;
- sensitive-route rate limiting;
- restrictive CSP, anti-framing and browser capability headers;
- credential/OAuth/JWT-like response redaction.

Supported native secret custody is Windows Credential Manager, macOS Keychain and Linux Secret Service. Each local encryption key is bound to the normalized absolute data directory, so a gate, smoke test or alternate installation cannot replace the key for the normal user profile. Missing native custody fails closed instead of creating a plaintext fallback.

## Detection architecture

The detector is provider-neutral. It evaluates current-message structure and intent, author-domain authentication alignment, organizational identity, Reply-To and relay behavior, relationship/thread context, URLs and HTML interactions, attachments and exact hashes, locally decoded QR URLs, personal policy, local campaign memory and verified signed community intelligence.

Authentication-Results are not trusted merely because they appear in MIME. SPF/DKIM/DMARC/ARC results become actionable only when the canonical acquisition boundary explicitly proves trusted provider provenance. Unproven live results remain non-authoritative rather than manufacturing trust or suspicion.

A failed, expired, tampered or untrusted signed community feed is treated as unavailable, never as evidence that a message is clean.

## Message actions

**Report Scam to Email Shield** creates immediate encrypted account-local campaign protection and may queue/send only privacy-reduced indicators to the community service. It does not move or delete mail. Optional exact-sender blocking is a separate decision.

**Move to Spam/Junk** and **Trash** operate on the exact selected provider message and require provider confirmation. They do not automatically create shared intelligence.

**Mark Safe**, **Trust sender**, sender/domain block/unblock and the Personal Policy Management Centre are account-scoped and persisted through encrypted local state.

## Unsubscribe safety

Email Shield supports manual web/mailto unsubscribe plus RFC 8058 one-click. Automatic one-click is available only when the bounded raw MIME has one unambiguous List-Unsubscribe/List-Unsubscribe-Post set, the One-Click declaration and HTTPS target are present, and a trusted passing DKIM identity correlates to exactly one raw DKIM signature whose signed-header list covers both required unsubscribe headers. Missing, ambiguous or untrusted proof falls back to manual unsubscribe. The browser still requires explicit confirmation before the credential-free, public-address-pinned HTTPS POST.

## Scan state and local history

- Quick, Full Mailbox and Spam/Junk scans use killable Workers and bounded provider progress.
- Interrupted/stopped scans use encrypted account-local resumable checkpoints; completed scans discard the checkpoint.
- Dashboard refresh does not cancel the Worker.
- Relationship history stores only HMAC identities and bounded aggregate observations; it never becomes an allowlist or positive trust score.
- Thread continuity uses bounded RFC `In-Reply-To` / `References` observations and deletes raw identifiers before scoring/browser output.
- Local encrypted/security-sensitive persistence reads are descriptor-bound and size-bounded before allocation; failed atomic replacement preserves the last good database.
- If an encrypted local-state file can no longer authenticate because its original native-vault key is unavailable, startup preserves it and names `npm run recover:local-state`. That explicit command archives only confirmed unreadable ciphertext with an integrity manifest before allowing clean state; it does not claim to decrypt data without the original key.

## Links, HTML, QR and attachments

- Link structure checks displayed-vs-actual destinations, shorteners, raw IPs, punycode, unusual ports and cross-domain sensitive actions.
- Explicit **Analyze Links** uses DNS/public-address validation and socket pinning on every redirect hop, keeps original Host/SNI/certificate verification, rejects non-public destinations, and bounds redirects/time/body size.
- HTML normalization is local/non-executing and covers anchors, BASE-relative links, forms/formaction, META refresh, entity-obfuscated destinations and companion plaintext URLs with fail-closed resource ceilings.
- PNG/JPEG QR images are decoded locally with strict byte/dimension/pixel/count/payload limits; only HTTP(S) URLs enter the canonical link pipeline.
- Attachment MIME/filename integrity, macro/archive/executable risk and bounded exact SHA-256 threat-intelligence matching are provider-neutral. Attachment bytes remain transient.

## Personal Policy Management

The selected account can manage blocked senders/domains, trusted senders, exact-message Safe exceptions, unsubscribe history and locally reported campaigns. Search/filter, single/bulk revoke, category clear, reset and strict policy-only JSON export/import are implemented. Import supports merge/replace with validation and rollback; credentials, sessions, vault references and provider tokens are excluded.

## Community intelligence

Community reports are privacy-reduced and reporter-deduplicated. Signed Ed25519 feed entries may represent campaign, sender, Reply-To domain, destination domain and attachment-hash indicators. Candidate/warning/confirmed thresholds are independent of one user's report.

A dedicated community-only service exposes only community health/report/feed/public-key/status surfaces. Normal desktop clients do not expose mailbox APIs through the community service. Public production deployment still requires the registered DNS/TLS, gateway, monitoring, recovery and abuse-control acceptance work.

## Engineering quality baseline

The Engineering Gate runs strict typecheck, production build, unit/API/regression tests, the full five-provider corpus, portable-core vectors, provider compatibility, approved Regression Vault, capacity/cost and public-document contracts, Worker runtime, browser source/privacy/wiring checks, compiled desktop/community/background smoke, reproducible package/signed lifecycle verification, dependency inventory and the production dependency audit on Windows, macOS and Ubuntu/Linux with real Linux Secret Service coverage.

The accepted Milestone 2 dependency graph currently has zero installed npm advisories. Future advisories are new evidence and must be reviewed; audit policy must not be weakened to hide them.

## Remaining Milestone 2 acceptance — not code-complete claims

These remain open until real owner/deployment evidence exists:

- **GAP-001:** production Google OAuth publication/consent verification;
- **GAP-002:** controlled real Microsoft/Outlook owner acceptance;
- **GAP-004:** public community deployment, DNS/TLS, monitoring, backup/restore and operational signing-key rotation;
- **GAP-005:** controlled real-destination Analyze Links validation;
- **GAP-008:** production gateway reporter reputation and volumetric/DDoS controls;
- required visible/manual acceptance items in `.engineering/REGRESSION_REGISTER.md`.

Run `npm run gate` before live acceptance. Follow `docs/MILESTONE_2_LIVE_ACCEPTANCE.md` and record only PASS/FAIL evidence—never credentials, OAuth codes/tokens, mailbox bodies or private provider identifiers.

## Public security and deployment documents

- `PRIVACY.md` — local/community data flows, retention, choices and deletion boundaries;
- `SECURITY.md` — private vulnerability disclosure and release/security policy;
- `THREAT_MODEL.md` — assets, trust boundaries, adversaries, controls and residual risk;
- `INCIDENT_RESPONSE.md` — severity, containment/recovery and scoped compromise playbooks;
- `docs/DEPLOYMENT_CAPACITY_COST.md` — executable workload/cost plan and deployment sizing;
- `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md` — canonical implemented/external/missing status.

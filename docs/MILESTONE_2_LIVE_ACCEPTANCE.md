# Milestone 2 — Live Acceptance Plan

This is the owner-controlled acceptance plan for Email Shield Milestone 2. Automated engineering evidence is necessary but does not replace real provider, external-destination, deployment or subjective browser acceptance.

## Evidence rules

Before testing, record the exact `main` commit SHA and latest successful post-merge Engineering Gate. Record only PASS/FAIL, test identifier, browser/OS when relevant and a short visible failure description.

Never record mailbox/app passwords, OAuth codes, access/refresh tokens, local-session values, private message bodies, private URL query strings, provider-native message IDs or signing keys. Use dedicated test accounts/messages for destructive actions.

Fixture mode is intentionally unavailable from normal consumer startup. `npm run dev:fixtures` is an engineering/owner test launcher that explicitly enables development entitlements. `npm run dev` is the production-like consumer launcher and must keep fixture/developer surfaces inaccessible. Do not set the development-entitlement environment variable manually for live consumer/provider acceptance.

## Phase A — Exact build and explicit fixture browser acceptance

1. Clean checkout the exact final `main`; run `npm ci` and `npm run gate`. Continue only when the report is PASSED.
2. Run `npm run dev:fixtures` and open `http://127.0.0.1:4173`.
3. **LIVE-A01 render/responsive** — stable non-blank render; desktop and narrow viewport readable; no permanent loading/error state.
4. **LIVE-A02 five providers** — connect Gmail, Outlook, iCloud, Yahoo and Generic IMAP in Fixture mode and complete visible Quick scans.
5. **LIVE-A03 scan modes** — run Quick, Full Mailbox Audit and Spam/Junk; counters/progress/results reset correctly and do not duplicate.
6. **LIVE-A04 stop/restart** — stop a Full scan while active and immediately start another scan without refreshing.
7. **LIVE-A05 action separation** — Report Scam, Move to Spam/Junk, Trash where offered, Mark Safe, Trust sender and Unsubscribe remain distinct actions with one visible owner each.
8. **LIVE-A06 replay rejection** — a completed action cannot execute again from rapid/repeated stale clicks; require rescan or a visible rejection.
9. **LIVE-A07 account isolation** — connect at least two fixture accounts and repeatedly switch; results, policy state, counters and actions never cross accounts.
10. **LIVE-A08 refresh/resume** — refresh during an eligible scan; active/resumable state reattaches without inventing a second worker.
11. **LIVE-A09 process restart** — leave a tab open, stop/restart the fixture process, attempt a harmless action in the old tab, verify clear reload/session-expired behavior, then reload and continue.

Stop the fixture process before Phase B. Fixture PASS proves the consumer workflow using controlled data; it does not prove any live provider.

## Phase B — Normal consumer boundary and Gmail live acceptance

Start a fresh process with `npm run dev`. Do not use `npm run dev:fixtures` in this phase.

- **LIVE-B01 consumer boundary** — the dashboard renders normally but Fixture mode/developer routes are not exposed or usable.
- **LIVE-B02 Gmail guided connect** — use Continue with Google, complete the approved desktop OAuth + PKCE flow and return through the one-time loopback callback. No client secret is required or shown.
- **LIVE-B03 account identity** — the Gmail account appears once with stable identity/label; no authorization code/access/refresh token is rendered.
- **LIVE-D03 Gmail Quick scan** — run a real Quick scan on a controlled populated Gmail mailbox. It should complete with bounded visible progress and normal result rows; credentials/tokens/provider-native IDs remain absent from UI/errors.
- **LIVE-D04 Gmail Full Mailbox Audit** — run a real Full Mailbox Audit on the same controlled mailbox. The default audit scope is Inbox + Spam + Archive and excludes Sent, Drafts and Trash. A populated mailbox must make visible forward progress and complete without the former quota-collapse behavior. Transient rate/quota responses may cause bounded retry/backoff but must not silently reset progress, create duplicate workers or turn incomplete inspection into Safe. A definitively vanished message may be skipped without collapsing the page; authorization/policy failures remain explicit failures.
- **LIVE-B05 Gmail Spam/Junk scan** — run the dedicated Spam/Junk scan; an empty Spam folder is a valid completed result rather than an error.
- **LIVE-B06 exact provider action** — on a dedicated message, exercise one Trash or Spam/Junk action and verify exactly that message changes after provider confirmation.
- **LIVE-B07 disconnect** — disconnect; UI must not claim success if provider revocation/local cleanup fails.
- **LIVE-B08 reconnect** — reconnect the same Gmail account and complete another Quick scan; account-scoped policy/history remains associated with the stable account identity.
- **LIVE-B09 GAP-001 publication** — complete Google’s required production consent/publication/verification for the intended public app and repeat external-user connect/scan/reconnect as required. GAP-001 remains open until the public application is actually accepted.

Any Gmail Full Mailbox Audit failure should be captured by visible symptom and timing only, without mailbox content. Reproduce it before changing code; do not compensate by reducing scan scope or loosening Safe/coverage rules.

## Phase C — Personal policy, report and resume behavior

Use fixture mode for non-destructive deterministic checks or a dedicated live mailbox when a provider mutation is specifically required.

- **LIVE-C01 Block/unblock sender** — block a controlled sender, rescan, verify block evidence, unblock and verify removal.
- **LIVE-C02 Block/unblock domain** — same for a controlled direct domain.
- **LIVE-C03 Mark Safe** — approve one controlled exact message; only that exception changes and incomplete/unreadable content cannot become Safe.
- **LIVE-C04 Trust sender** — trust a controlled sender and verify account-scoped policy state; hard threat evidence must still win.
- **LIVE-C05 Report Scam** — dialog explains local protection, privacy-reduced sharing and separate optional sender-block choice.
- **LIVE-C06 campaign memory** — report without moving, rescan and verify local campaign protection while provider folder remains unchanged.
- **LIVE-C07 Move to Spam/Junk** — use a different message; exactly that message moves and no community-report success is implied.
- **LIVE-C08 policy centre** — search/filter, single revoke, bulk revoke, category clear and reset on disposable state.
- **LIVE-C09 policy export/import** — exported JSON contains policy only, no credential/session/token/vault material; exercise merge and replace import.
- **LIVE-C10 scan refresh/resume** — active scan reattaches after refresh; eligible interrupted scan resumes from history without double-counting.
- **LIVE-C11 process interruption** — restart during resumable work; stale running record becomes interrupted/resumable rather than falsely complete.

## Phase D — Live iCloud, Yahoo and Generic IMAP

Use provider-approved app passwords only, never the normal account password.

- **LIVE-D01 iCloud** — connect, Quick scan, stop a longer scan, one exact controlled provider action, disconnect/reconnect; credentials never reappear after connection.
- **LIVE-D02 Yahoo** — repeat connect, Quick scan, one controlled provider action and reconnect when a controlled Yahoo account/app password is available.
- **LIVE-D05 Generic IMAP** — repeat against a controlled TLS IMAP account; verify configured host/port/user behavior, certificate validation, bounded scan and only capabilities actually supported by that server.

The Gmail identifiers LIVE-D03 and LIVE-D04 are intentionally reserved above because those two live regressions are the current highest-priority provider checks.

## Phase E — Live Outlook acceptance (GAP-002)

Outlook remains isolated from normal consumer onboarding until this controlled acceptance passes. Use the available Microsoft developer access to configure an Entra **public client / mobile and desktop application**. The guided flow uses Authorization Code + PKCE S256, dynamic `http://localhost:<port>` loopback callbacks and `offline_access`, `User.Read`, `Mail.ReadWrite`. Configure the mobile/desktop redirect as `http://localhost`; do not create/use a client secret for this public-client flow.

- **LIVE-E01 config** — controlled Outlook entry reports public desktop PKCE and expected permissions.
- **LIVE-E02 consent** — sign in to the controlled Microsoft account and approve only expected scopes.
- **LIVE-E03 callback** — localhost one-time callback returns to Email Shield without exposing code/token.
- **LIVE-E04 establishment** — account is added only after Graph profile + Inbox validation and protected credential custody succeed.
- **LIVE-E05 Quick scan** — real Outlook Quick scan completes with bounded progress.
- **LIVE-E06 provider action** — one dedicated message is moved to Spam/Junk or Trash and provider confirmation matches exactly that message.
- **LIVE-E07 disconnect/reconnect** — protected local credential is removed according to the Outlook contract, then the same account reconnects and scans normally.
- **LIVE-E08 stable identity** — policy/history remains tied to Graph account identity across refresh-token rotation/reconnect.
- **LIVE-E09 secret visibility** — client secret, auth code, access token and refresh token never render in dashboard/errors.

GAP-002 closes only after this real sequence passes. Developer access or fixture parity alone is not acceptance.

## Phase F — Controlled message-content corroboration

Use messages and infrastructure you control.

- **LIVE-F01 relationship history** — repeated benign sender history remains context, never automatic trust.
- **LIVE-F02 auth downgrade** — when provider Authentication-Results provenance has actually been proven, a controlled downgrade is surfaced rather than trusted.
- **LIVE-F03 Reply-To change** — stable historical Reply-To changing unexpectedly is surfaced as relationship evidence.
- **LIVE-F04 thread continuity** — real RFC references establish continuity; `Re:` text alone does not.
- **LIVE-F05 HTML destinations** — anchors/form actions/meta refresh are evidence without executing message HTML.
- **LIVE-F06 QR** — bounded PNG/JPEG QR URL extracts locally; malformed/oversized supported images do not freeze/crash or become Safe due to failed inspection.
- **LIVE-F07 attachment metadata/hash** — harmless controlled MIME mismatch warns appropriately; exact signed threat hash may activate without exposing filename/content to community state.
- **LIVE-F08 unsubscribe** — normal manual paths work; RFC 8058 automatic POST remains fail-closed unless trusted DKIM/provenance/signature-coverage proof exists and user confirmation is presented.

Do not mark Authentication-Results provenance trusted merely to make a scenario available.

## Phase G — Controlled Analyze Links validation (GAP-005)

Use deliberately managed public infrastructure only.

- **LIVE-G01 direct HTTPS** — bounded inspection succeeds on controlled public HTTPS.
- **LIVE-G02 public redirect** — redirect to another controlled public HTTPS endpoint re-resolves/re-pins.
- **LIVE-G03 private redirect** — loopback/RFC1918/link-local/non-public target is rejected.
- **LIVE-G04 mixed DNS** — public + non-public answer set is rejected rather than choosing a convenient public address.
- **LIVE-G05 content bounds** — unsupported/oversized/compressed content remains incomplete/uninspectable rather than benign.
- **LIVE-G06 transport privacy** — no mailbox cookies/provider Authorization headers are sent to analyzed destinations.

GAP-005 closes only after these controlled network cases pass on the production transport.

## Phase H — Public Community Shield deployment (GAP-004)

This is infrastructure acceptance, not a desktop browser test.

- deploy only the dedicated community entrypoint behind intended DNS/TLS/reverse proxy;
- prove dashboard/account/scan routes are absent;
- readiness is healthy only when aggregate build + sign + self-verification succeeds;
- encrypted report/feed state survives restart on persistent storage;
- monitoring covers health/error/capacity/storage/availability without report secrets or private key material;
- execute encrypted backup and restore into a fresh path, verify aggregate/signing state before cutover;
- execute real signing-key overlap, active-signer switch and retirement ceremony;
- restart after recovery/rotation and prove readiness/feed/report behavior remains correct.

GAP-004 remains open until that operational ceremony succeeds.

## Phase I — Gateway/reporter abuse controls (GAP-008)

- enforce gateway request/volume limits independently of application reporter dedupe;
- validate chosen reputation/enrollment controls without exposing mailbox identity;
- prove upstream volumetric/DDoS controls activate before application exhaustion;
- prove one reporter/device/source cannot manufacture warning/confirmed community state by volume alone;
- public errors under load remain generic and expose no paths, stacks, cryptographic state or attacker-controlled diagnostics.

GAP-008 closes only after the production gateway passes these controls.

## Phase J — Privacy-safe technical telemetry acceptance

Telemetry is optional and off until informed consent. The acceptance target is reliability measurement without surveillance.

1. Start the normal consumer build with `npm run dev` and confirm telemetry is disabled by default.
2. With a dedicated controlled installation, enable the product’s explicit technical telemetry consent.
3. Perform a small controlled lifecycle: app start, one provider connection outcome, one scan completion/failure classification, then consent disable/reset as supported.
4. Inspect the configured Email Shield analytics project and verify only closed allowlisted lifecycle/timing/error-classification properties appear.
5. Confirm there is no autocapture, session replay, page contents, message metadata, subject/body/recipient, mailbox/account identity, raw URL/query, provider token, device identity or raw exception text.
6. Disable consent and verify further product events stop. Resettable anonymous installation identity must not become an account identity.

At the 2026-08-16 reconciliation check, the connected Email Shield analytics project showed no application events in the recent project window. That is consistent with opt-in/off-by-default behavior, but it means live telemetry acceptance is still unproven and must not be recorded as PASS until the controlled consent test above is observed.

## Final Milestone 2 closure decision

Milestone 2 may be marked formally CLOSED only when all required conditions are true:

1. exact final `main` has a successful independent Windows/macOS/Ubuntu post-merge Engineering Gate;
2. required owner-visible register items pass;
3. Gmail Quick and Gmail Full Mailbox Audit live acceptance pass on the intended Google application/account boundary;
4. GAP-001 Google production publication is accepted or formally re-scoped by an approved product decision;
5. GAP-002 Outlook live owner acceptance passes;
6. GAP-004 deployed community operations passes;
7. GAP-005 controlled live Analyze Links acceptance passes;
8. GAP-008 gateway/reporter volumetric protection passes;
9. no reproducible code defect found during owner testing remains unresolved.

Until then the correct state is **Milestone 2 code-complete and ready for live/deployment acceptance**, not formally closed. Android/iOS shells remain deferred until this desktop/live boundary is stable.

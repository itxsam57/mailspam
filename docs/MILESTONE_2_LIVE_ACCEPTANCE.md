# Milestone 2 — Live Acceptance Plan

This is the owner-controlled acceptance plan for Email Shield Milestone 2. Automated engineering evidence is necessary but does not replace real provider, external-destination, deployment or subjective browser acceptance.

## Evidence rules

Before testing, record the exact `main` commit SHA and the latest successful post-merge Engineering Gate run. For each owner item record only `PASS` or `FAIL`, the test identifier, browser/OS when relevant and a short visible failure description.

Never record or share mailbox passwords, app passwords, OAuth authorization codes, access tokens, refresh tokens, local session values, private message bodies, private URL query strings, private provider message IDs or private signing keys.

Use dedicated test accounts/messages wherever an action moves mail, reports spam, unsubscribes or exercises public infrastructure.

## Phase A — Exact build and fixture browser acceptance

- **LIVE-A01 Exact build** — clean checkout of the exact final `main`; `npm ci`; `npm run gate`; continue only when the report is PASSED.
- **LIVE-A02 Initial render** — run `npm run dev`, open `http://127.0.0.1:4173`, verify a stable non-blank render and no permanent loading/error state.
- **LIVE-A03 Responsive UI** — verify desktop and narrow viewport readability and reachable controls.
- **LIVE-A04 Five fixture providers** — connect Gmail, Outlook, iCloud, Yahoo and Generic IMAP in Fixture mode and complete visible Quick scans.
- **LIVE-A05 Scan types** — run Quick, Full Mailbox and Spam/Junk fixture scans; verify counters/progress/results do not duplicate or stay stale.
- **LIVE-A06 Stop/restart** — stop a Full scan while active and immediately start another scan without refreshing.
- **LIVE-A07 Action separation** — confirm Report Scam, Move to Spam/Junk, Trash where offered, Mark Safe, Trust sender and unsubscribe remain distinct actions.
- **LIVE-A08 Replay feedback** — after one successful controlled fixture action, repeated/rapid reuse must require a rescan or visibly reject the stale action rather than executing twice.
- **LIVE-A09 Session refresh** — refresh the dashboard and continue ordinary fixture operations without being asked for any local session secret.
- **LIVE-A10 Process restart** — leave a tab open, restart `npm run dev`, try a harmless action in the stale tab, verify clear reload/session-expired behavior, then reload and continue normally.
- **LIVE-A11 Account isolation** — connect at least two fixture accounts and verify results, policies and message actions do not cross between them.

## Phase B — Personal policy, report and resume behavior

- **LIVE-B01 Block/unblock sender** — block a controlled fixture sender, rescan, verify block evidence, unblock, rescan and verify it disappears.
- **LIVE-B02 Block/unblock domain** — repeat with a controlled direct domain.
- **LIVE-B03 Mark Safe** — approve one controlled exact message and verify only that exception changes.
- **LIVE-B04 Trust sender** — trust one controlled sender and verify the account-scoped policy entry.
- **LIVE-B05 Report Scam** — on a controlled message, verify the dialog explains privacy-reduced sharing, local protection and the separate optional sender-block choice.
- **LIVE-B06 Immediate campaign memory** — report a controlled campaign without moving it, rescan and verify local campaign protection while the provider folder remains unchanged.
- **LIVE-B07 Move to Spam/Junk** — use a different controlled message; verify exactly that message moves and no shared-report success is implied.
- **LIVE-B08 Policy centre** — verify search/filter, single revoke, bulk revoke, category clear and reset on a disposable fixture policy state.
- **LIVE-B09 Policy export/import** — export policy-only JSON, inspect that it contains no credentials/session/token/vault material, then test merge and replace import on a controlled account.
- **LIVE-B10 Scan refresh/resume** — start a longer Full scan, refresh the dashboard and verify the scan continues; stop an eligible scan and resume it from scan history.
- **LIVE-B11 Process interruption** — interrupt/restart the app during a resumable scan and verify the stale running record becomes resumable/interrupted rather than falsely completed.

## Phase C — Live iCloud, Yahoo and Generic IMAP

Use provider-approved app passwords only; never the normal account password.

- **LIVE-C01 iCloud connect** — connect a controlled iCloud mailbox and confirm credentials are not displayed after connection.
- **LIVE-C02 iCloud Quick scan** — verify bounded progress, readable ordinary messages and HTML/multipart evidence where applicable.
- **LIVE-C03 iCloud Stop** — stop an active longer scan and verify controls recover promptly.
- **LIVE-C04 iCloud exact action** — on a dedicated test message, perform one provider action such as Spam/Junk or Trash and verify exactly one intended message changes after provider confirmation.
- **LIVE-C05 iCloud reconnect** — disconnect/reconnect using the protected credential flow and verify normal scanning returns.
- **LIVE-C06 Yahoo** — repeat connect, Quick scan, one controlled provider action and reconnect when a controlled Yahoo account/app password is available.
- **LIVE-C07 Generic IMAP** — repeat against a controlled TLS IMAP account; verify configured host/port/user behavior, bounded scans and exact provider action support available for that server.

## Phase D — Live Gmail regression and production publication

Configure the Google desktop OAuth client expected by Email Shield. Keep the client ID/installed-app client configuration local and never paste OAuth codes/tokens into test evidence.

- **LIVE-D01 Gmail guided connect** — launch guided Gmail connect, complete Google consent and return through the one-time loopback callback.
- **LIVE-D02 Gmail account identity** — verify the account appears once with a stable identity/label and no authorization code/access/refresh token is shown.
- **LIVE-D03 Gmail Quick scan** — complete a real Quick scan.
- **LIVE-D04 Gmail exact provider action** — on a dedicated message, exercise one exact Trash or Spam/Junk action and verify provider confirmation.
- **LIVE-D05 Gmail disconnect** — disconnect and verify the UI does not claim success if provider revocation/local cleanup fails.
- **LIVE-D06 Gmail reconnect** — reconnect the same account and complete another Quick scan; personal-policy identity must remain associated with the same account.
- **LIVE-D07 GAP-001 production publication** — complete the required Google production OAuth consent/publication/verification process for the intended public application, then repeat an external-user connect/scan/reconnect acceptance as applicable. GAP-001 stays open until this is actually accepted.

## Phase E — Live Outlook acceptance (GAP-002)

Create/configure a Microsoft Entra app registration as a **public client / mobile and desktop application**. Email Shield's guided flow uses Authorization Code + PKCE S256, dynamic `http://localhost:<port>` loopback callbacks and the scopes `offline_access`, `User.Read` and `Mail.ReadWrite`. Configure the mobile/desktop redirect as `http://localhost`. Do not create or enter a client secret for the guided Outlook flow.

Set the Email Shield Microsoft client ID locally through the expected environment/configuration path before starting the desktop app.

- **LIVE-E01 Outlook config visible** — the Outlook connect UI reports the public desktop PKCE flow and required permissions.
- **LIVE-E02 Consent** — start Outlook connect, sign in to the controlled Microsoft account and approve only the expected scopes.
- **LIVE-E03 Callback** — consent returns to Email Shield through the localhost one-time callback without showing the authorization code/token in the dashboard.
- **LIVE-E04 Account establishment** — Outlook account is added only after Graph profile + Inbox validation and protected local credential custody succeed.
- **LIVE-E05 Quick scan** — complete a real Outlook Quick scan with bounded progress.
- **LIVE-E06 Provider action** — on a dedicated message, exercise Spam/Junk or Trash and verify exactly the selected message changes after Graph/provider confirmation.
- **LIVE-E07 Disconnect** — disconnect; local protected credential is removed according to the Outlook disconnect contract without broad account-session revocation.
- **LIVE-E08 Reconnect** — reconnect the same Microsoft account and complete another Quick scan.
- **LIVE-E09 Stable identity** — after reconnect/refresh-token replacement, personal policy/history remains tied to the stable Graph account identity rather than the rotating token.
- **LIVE-E10 Secret visibility** — throughout the flow, client secret, auth code, access token and refresh token are never rendered in dashboard/errors.

Passing LIVE-E01 through LIVE-E10 closes the owner-acceptance portion of GAP-002. Any failure remains a real gap and must be fixed before Milestone 2 closure.

## Phase F — Relationship and thread behavior with controlled real mail

These are optional live corroboration of automated behavior when suitable controlled mailboxes are available.

- **LIVE-F01 Repeated benign sender** — receive multiple controlled benign messages from the same authenticated sender and verify history does not itself create a positive trust score/allowlist.
- **LIVE-F02 Authentication downgrade** — after established benign authenticated history, send a controlled message with a real authentication downgrade if your mail infrastructure can produce it; verify the downgrade is surfaced rather than silently trusted.
- **LIVE-F03 Reply-To change** — use a controlled sender whose previously stable Reply-To changes and verify the relationship anomaly is surfaced.
- **LIVE-F04 Thread continuity** — reply within a known controlled thread and verify normal continuity; a subject beginning `Re:` without actual RFC references must not alone create continuity.

If the provider's trusted Authentication-Results producer boundary has not been explicitly proven in Email Shield, authentication-derived live history remains conservative/unknown by design. Do not force production `providerTrust` merely to make this test pass.

## Phase G — HTML, QR, attachment and unsubscribe live corroboration

Use messages you control.

- **LIVE-G01 HTML destinations** — test ordinary anchors plus a controlled form/formaction or META refresh message; verify discovered destinations are visible as evidence without executing message HTML.
- **LIVE-G02 QR** — send a bounded PNG/JPEG containing an HTTP(S) QR URL and verify local URL extraction; malformed/oversized images must not freeze/crash or become automatically Safe because inspection failed.
- **LIVE-G03 Attachment MIME mismatch** — use controlled harmless files whose declared MIME/filename combination models a risky mismatch; verify the warning is based on metadata without uploading content.
- **LIVE-G04 Exact attachment hash** — if a controlled signed threat-feed hash is available, verify an exact matching bounded attachment activates that intelligence without exposing filename/content to community state.
- **LIVE-G05 Manual unsubscribe** — test a controlled `mailto:` and/or normal web List-Unsubscribe action.
- **LIVE-G06 RFC 8058 fail-closed** — a One-Click declaration without all trusted DKIM/provenance/signature-coverage proof must remain manual and must not POST automatically.
- **LIVE-G07 RFC 8058 compliant one-click** — only when a controlled provider path also has explicitly proven trusted Authentication-Results provenance, test a fully compliant one-click message; verify user confirmation appears before any POST. Do not mark live provider provenance trusted merely to make this scenario available.

## Phase H — Controlled real Analyze Links validation (GAP-005)

Use deliberately managed public infrastructure. Never point the test at private third-party destinations you do not control.

- **LIVE-H01 Direct public HTTPS** — analyze a controlled public HTTPS page and verify successful bounded inspection.
- **LIVE-H02 Public redirect** — use a controlled public redirect to another controlled public HTTPS endpoint and verify re-resolution/re-pinning.
- **LIVE-H03 Redirect to private address** — controlled redirect toward loopback/RFC1918/link-local/non-public target must be rejected.
- **LIVE-H04 Mixed DNS answers** — if your controlled DNS can return public + non-public answers, verify the destination is rejected rather than selecting a convenient public answer.
- **LIVE-H05 Unsupported/oversized/compressed content** — verify uninspectable content does not become benign.
- **LIVE-H06 Transport privacy** — confirm no mailbox cookies/provider Authorization headers are sent to the analyzed destination.

GAP-005 closes only after these controlled public-network cases pass on the production Analyze Links transport.

## Phase I — Public community deployment and operations (GAP-004)

This is deployment acceptance, not a desktop browser test.

- **LIVE-I01 Dedicated service** — deploy the community-only entry point; verify mailbox/dashboard/account/scan routes are not exposed.
- **LIVE-I02 DNS/TLS** — place it behind the intended public DNS/TLS/reverse-proxy boundary.
- **LIVE-I03 Health/readiness** — `/health` is healthy only when aggregate build + sign + self-verification succeeds; corrupt/unavailable state yields generic not-ready behavior.
- **LIVE-I04 Persistent encrypted state** — reports/feed state survives a controlled service restart from the intended persistent volume.
- **LIVE-I05 Monitoring** — configure health, error-rate, capacity/storage and availability monitoring without logging report secrets/private key material.
- **LIVE-I06 Encrypted backup** — run the reviewed backup operation using passphrase-file custody; verify the portable recovery bundle is produced.
- **LIVE-I07 Restore drill** — restore into a new path, validate aggregate/signing state and prove the service can read/sign/verify from the restored state before cutover.
- **LIVE-I08 Signing rotation ceremony** — prepare next key, publish overlap, switch active signer, verify clients trust the overlap as intended, then retire the old key according to the reviewed process.
- **LIVE-I09 Restart/recovery** — restart the deployed service after the above and verify readiness/feed/report behavior remains correct.

GAP-004 remains open until this operational ceremony is actually executed successfully.

## Phase J — Gateway/reporter abuse controls (GAP-008)

- **LIVE-J01 Edge rate limiting** — enforce gateway request/volume limits independently of application reporter dedupe.
- **LIVE-J02 Reputation/enrollment boundary** — implement and validate the chosen IP/device/reporter-reputation or enrollment controls without exposing mailbox identity to advertisers/other reporters.
- **LIVE-J03 Volumetric/DDoS protection** — verify the service remains protected under controlled load and upstream limits activate before application exhaustion.
- **LIVE-J04 Abuse threshold integrity** — prove one reporter/device/source cannot manufacture warning/confirmed community state by request volume alone.
- **LIVE-J05 Error privacy under load** — public errors remain generic and do not expose storage paths, stack traces, cryptographic state or attacker-controlled diagnostics.

GAP-008 closes only after the production gateway passes these controls.

## Final Milestone 2 closure decision

Milestone 2 may be marked formally CLOSED only when all of the following are true:

1. the exact final `main` has a successful post-merge Windows/macOS/Ubuntu Engineering Gate;
2. required manual visible items in `.engineering/REGRESSION_REGISTER.md` are PASS;
3. GAP-001 is accepted or explicitly re-scoped by an approved product decision;
4. GAP-002 Outlook live owner acceptance is PASS;
5. GAP-004 production community deployment/operations is PASS;
6. GAP-005 controlled live Analyze Links acceptance is PASS;
7. GAP-008 gateway/reporter volumetric protection is PASS;
8. no new reproducible code defect discovered during owner testing remains unresolved.

Until then the correct status is **Milestone 2 code-complete and ready for live/deployment acceptance**, not formally closed.

# Email Shield — Automated and Manual Test Matrix

This matrix is project-specific. A check is installed only when it protects an existing Email Shield architecture or workflow. The canonical desktop engineering gate now runs on Windows, macOS and Ubuntu; Linux additionally starts an isolated Secret Service user session for native vault verification.

## Automated engineering gate

| ID | Area | Check | Command | Platform | Gate behavior |
|---|---|---|---|---|---|
| A-01 | Environment | Node.js 22, required files, npm workspace and lockfile-v3 validation | `npm run preflight` | Windows + macOS + Ubuntu | Blocking |
| A-02 | Repository hygiene | Merge-marker, tracked-secret and targeted secret-pattern scan | `npm run preflight` | Windows + macOS + Ubuntu | Blocking |
| A-03 | Type safety | Strict TypeScript over production source and tests, no emit | `npm run typecheck` | Windows + macOS + Ubuntu | Blocking |
| A-04 | Production compilation | Compile `server/src` to `server/dist` | `npm run build` | Windows + macOS + Ubuntu | Blocking |
| A-05 | Unit/API behavior | Detection, MIME, provider normalization, policy, community privacy, aggregation, signatures, local API security, APIs and architecture | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-06 | Integration behavior | Entire scam corpus through all five provider fixtures | `npm run test:integration` | Windows + macOS + Ubuntu | Blocking |
| A-07 | Worker runtime | Compiled Worker startup, verified-feed input, progress and termination | `npm run test:integration` | Windows + macOS + Ubuntu | Blocking |
| A-08 | Browser source | Parse inline JavaScript and syntax-check every `web/*.js` file | `npm run check:web` | Windows + macOS + Ubuntu | Blocking |
| A-09 | Browser wiring | Required DOM, local security wrapper, dynamic scripts, Report Scam/Spam/Junk and API endpoint contracts | `npm run check:web` | Windows + macOS + Ubuntu | Blocking |
| A-10 | Browser privacy | No body, raw HTML, campaign payload, reporter proof, provider identifier or readable local-session secret in community/action UI | `npm run check:web` | Windows + macOS + Ubuntu | Blocking |
| A-11 | Server startup | Start compiled service on an isolated localhost port with loopback-only validation | `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-12 | API smoke | Homepage, accounts API, fixture connection, quick-scan SSE completion, authenticated local-session checks, community status and account removal | `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-13 | Corpus smoke | `/api/dev/test-suite` returns zero corpus/parity failures through the authenticated desktop API | `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-14 | Dependency inventory | Capture production/development advisory evidence | `npm run audit:inventory` | Ubuntu CI; local when enabled | Evidence/advisory |
| A-15 | Production dependencies | Fail on high or critical production advisories | `npm run audit:prod` | Ubuntu CI; local when enabled | Blocking |
| A-16 | Evidence | JSON/Markdown report, dependency evidence and browser handoff | `npm run gate` | Windows + macOS + Ubuntu | Always generated |
| A-17 | Provider Spam/Junk | Exact-one Gmail Spam, Outlook Junk, iCloud/Yahoo/IMAP special-use Junk behavior | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-18 | Adult campaign intent | Explicit adult-site campaign reaches High Risk without brand-specific rules | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-19 | Report privacy | Community context excludes subject/body/mailbox/provider/raw URL/attachment-name data | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-20 | Independent aggregation | Duplicate reporter, warning/confirmed thresholds, indicator support and rate limits | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-21 | Signed feed | Ed25519 signing, key-pair validation, tamper/trust/freshness/expiry rejection | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-22 | Community HTTP | Server mode disabled by default; ingestion/public key/signed feed contracts when enabled | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-23 | Local and offline protection | Immediate local campaign memory and encrypted retry outbox | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-24 | Provider parity | Gmail, iCloud, Outlook, Yahoo and Generic IMAP produce the same privacy-reduced report contract | `npm run test:unit` | Windows + macOS + Ubuntu | Blocking |
| A-25 | Local session boundary | HttpOnly process-local session, CSRF-protected reads, session expiry and absence of session material from HTML/browser storage | `npm run test:unit`, `npm run check:web`, `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-26 | Mutation replay defence | Exact same-origin proof, expiring one-time nonces and successful opaque-action replay rejection | `npm run test:unit`, `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-27 | Local network isolation | Loopback-only binding, Host allowlist, forwarded-header rejection and DNS-rebinding raw HTTP probe | `npm run test:unit`, `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-28 | Browser isolation | Per-response CSP nonce, anti-framing, same-origin opener/resource policy, no-referrer and restricted browser capabilities | `npm run test:unit`, `npm run check:web`, `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-29 | Local error privacy | Exact credentials, OAuth codes, bearer values and JWT-like values are redacted from API errors and SSE output | `npm run test:unit`, `npm run check:web` | Windows + macOS + Ubuntu | Blocking |
| A-30 | Bounded scan progress | Live IMAP Quick Scan preserves its ten-message limit while yielding smaller cumulative pages; remote community refresh cannot block worker startup; first-result and between-page stalls end visibly instead of leaving an endless EventSource | `scanProgressRuntime.test.ts`, `npm run smoke:server` | Windows + macOS + Ubuntu | Blocking |
| A-31 | Live IMAP text integrity | Truncation uses selected MIME-part limits rather than complete-message size; root single-part bodies use `TEXT`; bounded plain and HTML alternatives decode in one provider request; HTML destinations reach the canonical envelope; attachment bodies and full raw source remain unfetched | `imapMimeParts.test.ts`, architecture regression tests | Windows + macOS + Ubuntu | Blocking |
| A-32 | Credential vault boundary | Opaque target derivation, size validation, fail-closed unavailable backends, write/read/delete contract, secret-safe error handling, and native-store factory selection | `credentialVault.test.ts` | Windows + macOS + Ubuntu | Blocking |
| A-33 | App-password session custody | Long-lived iCloud/Yahoo/generic-IMAP sessions keep raw app passwords out of persistent session config when a native vault is available, resolve vault handles only at provider connect, preserve policy identity across password rotation, reference-count shared credentials, serialize reconnect/remove lifecycle, fail account creation on native write failure, keep last session on native delete failure, and use memory-only nonpersistent handles when the expected native service is unavailable | `secureSessionCredentials.test.ts`, strict type/build, existing Worker/server regression suites | Windows + macOS + Ubuntu | Blocking |
| A-34 | Guided Gmail OAuth | Desktop Authorization Code + PKCE S256, high-entropy state/nonce, exact random-port `127.0.0.1` callback Host/path/method, callback replay rejection, bounded token responses, verified Google ID-token nonce, stable `sub` policy identity, native-vault/memory-only refresh-token custody, validation+commit serialization, final-account provider revocation, revocation-failure truthfulness and browser token/code privacy | `gmailOAuthSecurity.test.ts`, `gmailOAuthRevocation.test.ts`, `npm run check:web`, strict type/build | Windows + macOS + Ubuntu | Blocking |
| A-35 | Guided Outlook OAuth | Microsoft public desktop Authorization Code + PKCE S256, exact `offline_access`/`User.Read`/`Mail.ReadWrite` scopes, no guided client secret, random localhost callback with IPv4 loopback listener, state/replay protection, Graph `/me.id` stable identity, native-vault refresh-token custody, same-reference token rotation, account-mismatch rejection, rotation-write fail-closed behavior and browser token/code privacy | `microsoftOAuthSecurity.test.ts`, `outlookRefreshRotation.test.ts`, `npm run check:web`, strict type/build | Windows + macOS + Ubuntu | Blocking |
| A-36 | Personal-policy encryption-key custody | No new raw `personal-policy.key`; legacy-key migration authenticates the encrypted database, writes/reads back the same `local-encryption-key` through an available native vault before deleting the legacy key, fails closed on missing/conflicting/unreadable key state, and uses memory-only policy state rather than plaintext fallback when no persistent native service is available | `policyKeyVaultMigration.test.ts`, `policyKeyWindowsNative.test.ts`, `policyPersistence.test.ts`, strict type/build | Windows + macOS + Ubuntu contract; Windows real legacy migration | Blocking |
| A-37 | Cross-platform native vaults | Windows Credential Manager, macOS Keychain and Linux Secret Service use the shared opaque-reference contract; native write secrets stay out of argv and shell execution; macOS writes use SecurityTool interactive stdin; Linux writes use `secret-tool` stdin inside a real Secret Service login-session bus; each desktop backend performs a real ephemeral native write/read/delete round trip in CI | `credentialVault.test.ts`, `macosKeychainVault.test.ts`, `linuxSecretServiceVault.test.ts`, three-platform CI | Windows + macOS + Ubuntu native round trips | Blocking |

## Final visible browser test — owner only

After a green gate, the generated handoff contains only subjective/visible checks:

1. page rendering and responsive layout;
2. all five fixture-provider scans;
3. Safe and warning-card action presentation;
4. Report Scam privacy and independent-reporting confirmation text;
5. immediate local campaign protection after a rescan;
6. optional sender block remaining separate;
7. Move to Spam/Junk remaining separate and exact-message only;
8. Stop/restart responsiveness and account isolation;
9. visible local-session behavior after refresh and process restart;
10. duplicate successful action controls requiring a rescan;
11. controlled live iCloud presentation when credentials are available;
12. live provider scans show bounded-batch status at least every 15 seconds, produce partial results as batches complete, or stop with a specific timeout error rather than remaining indefinitely on Scanning;
13. ordinary short live iCloud messages no longer uniformly show the former `Readable text was bounded to 24576 bytes` note, and HTML-only/multipart messages show available content and link evidence;
14. guided Gmail live connect, Quick Scan, Disconnect, reconnect and post-reconnect Quick Scan remain accepted and must not regress;
15. guided Outlook opens Microsoft consent as a public desktop client, returns to Email Shield without exposing code/tokens, adds the Outlook account, completes Quick Scan, Disconnect removes the local protected credential, and reconnect + Quick Scan succeeds with stable policy identity despite refresh-token replacement.

The local session, CSRF, nonce, Host, redaction, bounded scan deadlines, selected-part MIME decoding, warning/confirmed aggregation, cryptographic feed verification, cross-provider report contract, app-password ownership lifecycle, Gmail OAuth lifecycle, Microsoft PKCE/stable-identity/token-rotation contracts, personal-policy key migration rules and all three desktop native vault backends are automated. Real provider authorization and mailbox acceptance remain owner-controlled because CI receives no live mailbox credentials.

## Not applicable

| Area | Reason |
|---|---|
| Relational DB migrations/RLS/seeds | Encrypted local JSON stores are used; no relational database exists. |
| Component-framework tests | UI is vanilla HTML/JavaScript. |
| Mobile-native build | No Android/iOS native project exists. |
| Docker/Kubernetes | No container definition is currently canonical. |
| Production cloud health | No public deployment target is connected to CI. |
| Visual snapshots | Owner performs final visible acceptance. |
| Real provider destructive CI | CI must never receive mailbox credentials or modify live mail. |
| Gateway/DDoS testing | Requires the actual production reverse proxy/API gateway. |

## Change-impact rule

Every future provider, OAuth flow, credential store, report indicator, threshold, key format, storage layer, external endpoint or user-visible action must update this matrix and add applicable automated protection.

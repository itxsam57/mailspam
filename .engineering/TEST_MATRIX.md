# Email Shield — Automated and Manual Test Matrix

This matrix is project-specific. A check is installed only when it protects an existing Email Shield architecture or workflow.

## Automated engineering gate

| ID | Area | Check | Command | Platform | Gate behavior |
|---|---|---|---|---|---|
| A-01 | Environment | Node.js 22, required files, npm workspace and lockfile-v3 validation | `npm run preflight` | Windows + Ubuntu | Blocking |
| A-02 | Repository hygiene | Merge-marker, tracked-secret and targeted secret-pattern scan | `npm run preflight` | Windows + Ubuntu | Blocking |
| A-03 | Type safety | Strict TypeScript over production source and tests, no emit | `npm run typecheck` | Windows + Ubuntu | Blocking |
| A-04 | Production compilation | Compile `server/src` to `server/dist` | `npm run build` | Windows + Ubuntu | Blocking |
| A-05 | Unit/API behavior | Detection, MIME, provider normalization, policy, community privacy, aggregation, signatures, APIs and architecture | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-06 | Integration behavior | Entire scam corpus through all five provider fixtures | `npm run test:integration` | Windows + Ubuntu | Blocking |
| A-07 | Worker runtime | Compiled Worker startup, verified-feed input, progress and termination | `npm run test:integration` | Windows + Ubuntu | Blocking |
| A-08 | Browser source | Parse inline JavaScript and syntax-check every `web/*.js` file | `npm run check:web` | Windows + Ubuntu | Blocking |
| A-09 | Browser wiring | Required DOM, dynamic scripts, Report Scam/Spam/Junk and API endpoint contracts | `npm run check:web` | Windows + Ubuntu | Blocking |
| A-10 | Browser privacy | No body, raw HTML, campaign payload, reporter proof or provider identifier in community UI | `npm run check:web` | Windows + Ubuntu | Blocking |
| A-11 | Server startup | Start compiled service on an isolated localhost port | `npm run smoke:server` | Windows + Ubuntu | Blocking |
| A-12 | API smoke | Homepage, accounts API, fixture connection, quick-scan SSE completion, community status and account removal | `npm run smoke:server` | Windows + Ubuntu | Blocking |
| A-13 | Corpus smoke | `/api/dev/test-suite` returns zero corpus/parity failures | `npm run smoke:server` | Windows + Ubuntu | Blocking |
| A-14 | Dependency inventory | Capture production/development advisory evidence | `npm run audit:inventory` | Ubuntu CI; local when enabled | Evidence/advisory |
| A-15 | Production dependencies | Fail on high or critical production advisories | `npm run audit:prod` | Ubuntu CI; local when enabled | Blocking |
| A-16 | Evidence | JSON/Markdown report, dependency evidence and browser handoff | `npm run gate` | Windows + Ubuntu | Always generated |
| A-17 | Provider Spam/Junk | Exact-one Gmail Spam, Outlook Junk, iCloud/Yahoo/IMAP special-use Junk behavior | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-18 | Adult campaign intent | Explicit adult-site campaign reaches High Risk without brand-specific rules | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-19 | Report privacy | Community context excludes subject/body/mailbox/provider/raw URL/attachment-name data | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-20 | Independent aggregation | Duplicate reporter, warning/confirmed thresholds, indicator support and rate limits | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-21 | Signed feed | Ed25519 signing, key-pair validation, tamper/trust/freshness/expiry rejection | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-22 | Community HTTP | Server mode disabled by default; ingestion/public key/signed feed contracts when enabled | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-23 | Local and offline protection | Immediate local campaign memory and encrypted retry outbox | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-24 | Provider parity | Gmail, iCloud, Outlook, Yahoo and Generic IMAP produce the same privacy-reduced report contract | `npm run test:unit` | Windows + Ubuntu | Blocking |

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
9. controlled live iCloud presentation when credentials are available.

The warning/confirmed aggregation, cryptographic feed verification and cross-provider report contract are automated. Public DNS/TLS/gateway/monitoring are deployment acceptance, not browser acceptance.

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

Every future provider, report indicator, threshold, key format, storage layer, external endpoint or user-visible action must update this matrix and add applicable automated protection.
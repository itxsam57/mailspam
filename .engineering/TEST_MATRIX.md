# Email Shield — Automated and Manual Test Matrix

This matrix is project-specific. A check is installed only when it protects an existing Email Shield architecture or workflow.

## Automated engineering gate

| ID | Area | Check | Command | Platform | Gate behavior |
|---|---|---|---|---|---|
| A-01 | Environment | Node.js 22, required files, npm workspace and lockfile-v3 validation | `npm run preflight` | Windows + Ubuntu | Blocking |
| A-02 | Repository hygiene | Merge-conflict marker, tracked secret-file and targeted secret-pattern scan | `npm run preflight` | Windows + Ubuntu | Blocking |
| A-03 | Type safety | Strict TypeScript over production source and tests, no emit | `npm run typecheck` | Windows + Ubuntu | Blocking |
| A-04 | Production compilation | Compile `server/src` to `server/dist` | `npm run build` | Windows + Ubuntu | Blocking |
| A-05 | Unit behavior | Detection layers, verdict hierarchy, provider normalization, MIME, policies, unsubscribe, privacy and architecture regressions | `npm run test:unit` | Windows + Ubuntu | Blocking |
| A-06 | Integration behavior | Entire scam corpus through all five provider fixtures | `npm run test:integration` | Windows + Ubuntu | Blocking |
| A-07 | Worker runtime | Compiled Worker startup, progress and termination behavior | `npm run test:integration` | Windows + Ubuntu | Blocking |
| A-08 | Browser source | Parse inline JavaScript and run Node syntax checks on every `web/*.js` file | `npm run check:web` | Windows + Ubuntu | Blocking |
| A-09 | Browser wiring | Required DOM IDs, dynamic script dependencies and browser-to-server endpoint contract | `npm run check:web` | Windows + Ubuntu | Blocking |
| A-10 | Browser privacy boundary | No message body/raw HTML/raw unsubscribe target fields in browser action scripts | `npm run check:web` | Windows + Ubuntu | Blocking |
| A-11 | Server startup | Start compiled service on an isolated localhost port and wait for readiness | `npm run smoke:server` | Windows + Ubuntu | Blocking |
| A-12 | API smoke | Homepage, accounts API, fixture connection, quick-scan SSE completion and account removal | `npm run smoke:server` | Windows + Ubuntu | Blocking |
| A-13 | Detection suite smoke | `/api/dev/test-suite` produces zero fixture false positives, false negatives and parity failures | `npm run smoke:server` | Windows + Ubuntu | Blocking |
| A-14 | Dependency security | Production dependency audit at high severity | `npm run audit:prod` | Ubuntu CI; local full gate when network available | Blocking when enabled |
| A-15 | Evidence | JSON and Markdown gate report plus browser handoff artifact | `npm run gate` | Windows + Ubuntu | Always generated, including on failure |

## Existing automated coverage retained

The gate does not replace or weaken the existing regressions. It preserves coverage for:

- canonical envelope normalization across Gmail, iCloud, Outlook, Yahoo and generic IMAP fixtures;
- SPF/DKIM/DMARC and identity/reply-to alignment;
- malicious/legitimate corpus parity across five providers;
- bounded MIME part selection without attachment-body downloads;
- partial/unknown/review/high-risk/confirmed verdict precedence;
- worker isolation, Windows compiled Worker path, stop and retry behavior;
- account-scoped block/trust/approval rules and encrypted persistence;
- exact-one-message reversible Trash operations;
- one-click, link-only and mailto unsubscribe security;
- SSRF/private-network protection for explicit link actions;
- privacy-reduced diagnostics and Safe audit;
- provider-neutral Mark Safe, Trust sender and unsubscribe actions.

## Final visible browser test — owner only

The automated gate stops before subjective visual acceptance. After a green gate, the generated `artifacts/engineering/MANUAL_TEST_HANDOFF.md` lists only the remaining visible checks:

1. page rendering and responsive layout;
2. visible connection and scan controls;
3. fixture-provider switching and scan presentation;
4. Safe audit presentation and actions;
5. warning-card action confirmations and visible feedback;
6. stop/restart responsiveness;
7. controlled live iCloud presentation and action confirmation when credentials are available;
8. visible errors, loading states, rapid-click resistance and absence of blank/frozen UI.

Gmail and Outlook live OAuth are not included as pass criteria because guided browser onboarding is an acknowledged unimplemented product gap.

## Not applicable

| Area | Reason |
|---|---|
| Database migrations/RLS/seed idempotency | No application database or migration layer exists. |
| Component-framework tests | Browser UI is vanilla HTML/JavaScript. |
| Mobile-native build | No Android/iOS native project exists. |
| Docker/Kubernetes | No container deployment is part of the current localhost milestone. |
| Cloud deployment health | No production deployment target is configured. |
| Visual snapshot automation | Owner performs final visible browser acceptance; automation must not substitute subjective acceptance. |
| Real provider destructive tests in CI | CI must never receive mailbox credentials or modify a live mailbox. |

## Change-impact rule

Every future change must update this matrix when it introduces a new runtime, data store, provider path, destructive action, external integration or user-visible workflow. New automated checks should be added only when the project actually gains the corresponding architecture.
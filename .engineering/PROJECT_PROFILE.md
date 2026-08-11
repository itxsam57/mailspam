# Email Shield — Project Engineering Profile

Generated from the mandatory repository audit in the AI Engineering Automation Kit, Section 00.

## Repository identity

| Field | Value |
|---|---|
| Project name | Email Shield |
| Repository | `itxsam57/mailspam` |
| Canonical branch | `main` |
| Application type | Local-first email scam-detection client plus an optional self-hosted community intelligence service |
| Backend framework | Express `4.19.x` |
| Frontend | Vanilla HTML, CSS and browser JavaScript served by Express |
| Language | TypeScript for server/engine/tests; JavaScript and HTML for browser UI |
| TypeScript version | `5.9.x` |
| Package manager | npm with lockfile v3 |
| Workspace root | Repository root |
| Application workspace | `server/` |
| Supported CI runtime | Node.js 22 |

Database/migrations/seeds: not applicable. The current service uses encrypted local files and has no relational database, ORM or migration system.

## Application roots and entry points

- Repository/workspace root: `package.json`
- Server workspace: `server/package.json`
- Runtime entry point: `server/src/index.ts`
- Express application factory: `server/src/api/server.ts`
- Browser entry document: `web/index.html`
- Browser action layers: `web/scan-monitor.js`, `web/unsubscribe-monitor.js`, `web/review-actions.js`, `web/safe-audit.js`
- Community reporting client/server: `server/src/community/`
- Signed-feed consumer: `server/src/engine/layers/globalIntelligence.ts`
- Compiled runtime output: `server/dist/` (generated and ignored)

## Repository layout

| Area | Location |
|---|---|
| Provider adapters | `server/src/adapters/` |
| Canonical email contracts | `server/src/canonical/` |
| API/session/persistence | `server/src/api/` |
| Community reporting, aggregation and signing | `server/src/community/` |
| Detection engine | `server/src/engine/` |
| Workflows | `server/src/workflows/` |
| Worker runtime | `server/src/workers/` |
| Utilities | `server/src/util/` |
| Browser assets | `web/` |
| Unit and API-contract tests | `tests/unit/` |
| Integration tests | `tests/integration/` |
| Synthetic email fixtures | `fixtures/scam-corpus/` |
| Project documentation | `README.md`, `README_REBUILD_STATUS.md`, `docs/`, `.engineering/` |
| CI | `.github/workflows/verify.yml` |
| Engineering automation | `.engineering/`, `scripts/engineering/` |

## Exact commands

| Purpose | Command | Notes |
|---|---|---|
| Locked install | `npm ci` | Required in CI and clean verification environments. |
| Development start | `npm run dev` | Builds first, then starts on `127.0.0.1:4173` by default. |
| Production start | `npm start` | Requires a successful build first. |
| Typecheck | `npm run typecheck` | Strict TypeScript check over source and tests, no emit. |
| Build | `npm run build` | Compiles production server code to `server/dist/`. |
| Unit tests | `npm run test:unit` | Detection, privacy, API, signing, aggregation and architecture suites. |
| Integration tests | `npm run test:integration` | Corpus and compiled Worker runtime suites. |
| Browser/static checks | `npm run check:web` | Validates HTML/JS wiring, privacy boundaries and syntax. |
| Provider compatibility | `npm run check:provider-compatibility` | Replays the reviewed v1 compiled capability/fixture contract for all five providers. |
| Regression Vault | `npm run check:regression-vault` | Verifies approved anonymized sample provenance, hashes and all-five-provider outcomes. |
| Server/API smoke | `npm run smoke:server` | Starts the compiled server and exercises fixture/API/SSE paths. |
| Full dependency inventory | `npm run audit:inventory` | Writes package-level advisory evidence without rewriting dependencies. |
| Production dependency audit | `npm run audit:prod` | Fails on high or critical production vulnerabilities. |
| Full engineering gate | `npm run gate` | Runs every applicable automated gate and writes reports. |
| Existing compatibility command | `npm run verify` | Alias of the full engineering gate. |

## Community deployment modes

### Desktop/client mode — default

No community ingestion or public feed is served. The client may use embedded fixture/single-node intelligence or a configured remote service. Local API remains bound to localhost.

### Central community service — explicit

Set `EMAIL_SHIELD_COMMUNITY_SERVER=1`. This enables privacy-reduced report ingestion and signed feed/public-key endpoints. A production deployment additionally requires HTTPS, a reverse proxy/API gateway, authentication/rate limiting at the edge, monitoring, backups and protected signing-key operations. See `.engineering/COMMUNITY_DEPLOYMENT.md`.

## Environment variables

| Variable | Secret | Use |
|---|---|---|
| `PORT` | No | HTTP port; defaults to `4173`. |
| `HOST` | No | Bind address; defaults to `127.0.0.1`. |
| `EMAIL_SHIELD_DATA_DIR` | No | Encrypted policy/community storage location. |
| `EMAIL_SHIELD_COMMUNITY_URL` | No | HTTPS base URL for the central community service; localhost HTTP is permitted only for development. |
| `EMAIL_SHIELD_COMMUNITY_SERVER` | No | `1` explicitly enables central ingestion/feed serving. Disabled by default. |
| `EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS` | No | JSON array or PEM public key(s) trusted by clients for Ed25519 feed verification. |
| `EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY` | **Yes** | Optional central Ed25519 private signing key supplied through secret management. |
| `EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY` | No | Public half paired with the configured private signing key. |
| `ENGINEERING_AUDIT` | No | `1` enables dependency inventory and blocking production audit. |
| `ENGINEERING_ARTIFACT_DIR` | No | Optional automation report output directory. |

Mailbox OAuth credentials, app passwords, community private signing keys and provider tokens are runtime secrets. They must not be committed, logged, embedded in test artifacts or included in handoff reports.

## Privacy and persistence boundary

Community reports may contain only pseudonymous reporter proof, campaign fingerprint, eligible exact sender, unrelated Reply-To/destination organizational domains, attachment hashes, evidence codes, score and verdict. They must not contain mailbox address/proof, subject, message body, contacts, credentials, provider message IDs, raw URL paths/query values, attachment names or attachment content.

Persistent data under `~/.email-shield/` unless overridden:

- encrypted personal policy database;
- encrypted locally reported campaign memory;
- encrypted community outbox;
- encrypted central aggregate database when server mode is enabled;
- local HMAC reporter-identity key;
- Ed25519 signing key pair for embedded/server mode;
- public signed-feed cache, useful only while signature and freshness checks pass.

## Test runner and generated output

- Runner: Vitest `2.1.x`
- Configuration: `server/vitest.config.ts`
- Included tests: `tests/**/*.test.ts`
- Test timeout: 20 seconds
- Automation output: `artifacts/engineering/` (generated and ignored)
- Compiled output: `server/dist/` (generated and ignored)

## Deliberately not installed

These checks remain inapplicable without an architecture change:

- React/Next/Vite component checks
- relational database migrations or ORM checks
- Docker/Kubernetes checks
- mobile-native build checks
- browser snapshots as a replacement for owner-visible acceptance
- live destructive mailbox actions in CI
- public cloud health checks before a real deployment target exists

A repository-green community service is self-hostable code, not proof of a publicly operated production network. DNS/TLS, edge controls, monitoring, backups and signing-key rotation are deployment responsibilities and remain recorded honestly.

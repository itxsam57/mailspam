# Email Shield — Project Engineering Profile

Generated from the mandatory repository audit in the AI Engineering Automation Kit, Section 00.

## Repository identity

| Field | Value |
|---|---|
| Project name | Email Shield |
| Repository | `itxsam57/mailspam` |
| Audited base branch | `main` |
| Audited functional base commit | `18d7a7b657762afb79d304f1cfac4cecdae7468b` |
| Application type | Local-first email scam-detection service with a browser dashboard |
| Backend framework | Express `4.19.x` |
| Frontend | Vanilla HTML, CSS and browser JavaScript served by Express |
| Language | TypeScript for server/engine/tests; JavaScript and HTML for browser UI |
| TypeScript version | `5.9.x` |
| Package manager | npm with lockfile v3 |
| Workspace root | Repository root |
| Application workspace | `server/` |
| Supported CI runtime | Node.js 22 |

## Application roots and entry points

- Repository/workspace root: `package.json`
- Server workspace: `server/package.json`
- Runtime entry point: `server/src/index.ts`
- Express application factory: `server/src/api/server.ts`
- Browser entry document: `web/index.html`
- Browser action layers: `web/scan-monitor.js`, `web/unsubscribe-monitor.js`, `web/review-actions.js`, `web/safe-audit.js`
- Compiled runtime output: `server/dist/` (generated and ignored)

## Repository layout

| Area | Location |
|---|---|
| Provider adapters | `server/src/adapters/` |
| Canonical email contracts | `server/src/canonical/` |
| API/session/persistence | `server/src/api/` |
| Detection engine | `server/src/engine/` |
| Workflows | `server/src/workflows/` |
| Worker runtime | `server/src/workers/` |
| Utilities | `server/src/util/` |
| Browser assets | `web/` |
| Unit tests | `tests/unit/` |
| Integration tests | `tests/integration/` |
| Synthetic email fixtures | `fixtures/scam-corpus/` |
| Project documentation | `README.md`, `README_REBUILD_STATUS.md`, `docs/` |
| CI | `.github/workflows/verify.yml` |
| Engineering automation | `.engineering/`, `scripts/engineering/` |

## Exact commands

| Purpose | Command | Notes |
|---|---|---|
| Locked install | `npm ci` | Required in CI and clean verification environments. |
| Developer install | `npm install` | Permitted for local setup; must not leave lockfile drift. |
| Development start | `npm run dev` | Builds first, then starts on `127.0.0.1:4173` by default. |
| Production start | `npm start` | Requires a successful build first. |
| Typecheck | `npm run typecheck` | Strict TypeScript check over source and tests, no emit. |
| Build | `npm run build` | Compiles production server code to `server/dist/`. |
| Unit tests | `npm run test:unit` | Vitest unit suites only. |
| Integration tests | `npm run test:integration` | Corpus and compiled Worker runtime suites. |
| All tests | `npm test` | Existing full Vitest command; builds first. |
| Browser/static checks | `npm run check:web` | Validates HTML/JS wiring and syntax without adding a browser framework. |
| Server/API smoke | `npm run smoke:server` | Starts the compiled server on an isolated port and exercises fixture/API/SSE paths. |
| Production dependency audit | `npm run audit:prod` | Fails on high or critical production vulnerabilities. |
| Full engineering gate | `npm run gate` | Runs every applicable automated gate and writes reports. |
| Existing compatibility command | `npm run verify` | Alias of the full engineering gate after installation. |

## Test runner and configuration

- Runner: Vitest `2.1.x`
- Configuration: `server/vitest.config.ts`
- Test root: repository root
- Included tests: `tests/**/*.test.ts`
- Test timeout: 20 seconds
- Production compiler: `server/tsconfig.build.json`
- Strict source/test compiler: `server/tsconfig.json`

## Environment variables

| Variable | Secret | Use |
|---|---|---|
| `PORT` | No | Local HTTP port; defaults to `4173`. |
| `HOST` | No | Bind address; defaults to `127.0.0.1`. |
| `EMAIL_SHIELD_DATA_DIR` | No | Optional local encrypted-policy storage location. |
| `ENGINEERING_AUDIT` | No | Automation-only switch; `1` enables production dependency audit. |
| `ENGINEERING_ARTIFACT_DIR` | No | Optional automation report output directory. |

Mailbox OAuth credentials, app passwords and provider tokens are runtime secrets. They must not be committed, logged, embedded in test artifacts, or included in handoff reports.

## Generated, ignored and persistent data

- Ignored generated directories/files: `node_modules/`, `dist/`, `coverage/`, `.vitest/`, logs, `test-report.json`, `.env*` except `.env.example`, IDE files and OS metadata.
- Automation output: `artifacts/engineering/` (generated and ignored).
- Encrypted local policy database: outside the repository under `~/.email-shield/` unless overridden.
- Database/migrations/seeds: not applicable; this repository has no relational/application database or migration system.
- Fixtures: deterministic `.eml` corpus under `fixtures/scam-corpus/` plus its manifest and corpus builder.

## CI baseline before automation installation

The pre-installation workflow used Node.js 22 on Ubuntu and Windows, ran `npm ci`, `npm run verify`, and a Linux production dependency audit. The audited functional base commit had a green matrix. No pre-existing automated failure was observed at the installation baseline.

## Deliberately not installed

These checks are not applicable to the current repository and must not be added without an architecture change:

- React, Next.js, Vite or component-framework checks
- Database migration, schema, seed or ORM checks
- Docker/Kubernetes checks
- Mobile-native build checks
- Playwright/Cypress visual acceptance as a replacement for the owner’s final visible browser test
- Cloud deployment checks; the current application is a localhost hard-test build

ESLint and coverage-provider packages were not added because the repository has no existing configuration or lockfile entries for them. Strict TypeScript, Vitest regressions, Node syntax validation and architecture tests provide the applicable no-new-dependency gate. Adding a new lint/coverage stack requires a separate reviewed dependency change.
# PostHog Private Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in PostHog engineering telemetry that cannot export mailbox or user data and cannot break Email Shield when telemetry fails.

**Architecture:** Keep telemetry behind one server-side boundary with a closed event/property schema and a fail-soft HTTP transport. Use Node's built-in `fetch` rather than adding a dependency, then call the boundary only from desktop startup lifecycle points.

**Tech Stack:** TypeScript, Node.js built-in fetch, Vitest, existing GitHub Engineering Gate.

## Global Constraints

- Telemetry is disabled unless `EMAIL_SHIELD_TELEMETRY=1`.
- No PostHog token is committed to this public repository.
- No email content, email metadata, account identity, device identity, credentials, OAuth data, personal policy contents, session replay, or autocapture may leave the device.
- Unknown events and unknown properties fail closed.
- Telemetry failures never change application startup behavior.

---

### Task 1: Privacy contract

**Files:**
- Test: `tests/unit/technicalTelemetry.test.ts`
- Create: `server/src/telemetry/technicalTelemetry.ts`

**Interfaces:**
- Produces: `createTechnicalTelemetryFromEnvironment(options)` and `TechnicalTelemetry.capture(event, properties?) -> Promise<boolean>`.

- [x] **Step 1: Write the failing test** defining opt-in, exact payload, sensitive-field rejection, and fail-soft network behavior.
- [ ] **Step 2: Verify RED** through the pull-request Engineering Gate; expected failure is unresolved `server/src/telemetry/technicalTelemetry.js`.
- [ ] **Step 3: Implement the minimum telemetry boundary** with a fixed event schema, fixed property schema, HTTPS PostHog endpoint, timeout, and no-op behavior when disabled.
- [ ] **Step 4: Verify GREEN** by running the unit suite and full Engineering Gate.

### Task 2: Desktop lifecycle integration

**Files:**
- Modify: `server/src/index.ts`
- Test: `tests/unit/technicalTelemetry.test.ts`

**Interfaces:**
- Consumes: `createTechnicalTelemetryFromEnvironment` from Task 1.
- Produces: startup lifecycle events only.

- [ ] **Step 1: Add/extend the test** to lock the permitted event names and fixed failure classification.
- [ ] **Step 2: Emit app-started, protected-state-ready/failed, and server-listening events** without awaiting success-path telemetry and while preserving the original failure on protected-state initialization.
- [ ] **Step 3: Run unit tests, typecheck, build, and full Engineering Gate** on Linux, Windows, and macOS.

### Task 3: Activation documentation

**Files:**
- Create: `docs/technical-telemetry.md`

- [ ] **Step 1: Document the three runtime variables** without including any secret value.
- [ ] **Step 2: Document the exact data that may and may not be sent.**
- [ ] **Step 3: Verify public docs and full Engineering Gate.**

### Completion Gate

Merge only after the PR's cross-platform Engineering Gate is green. After merge, confirm PostHog ingestion when Email Shield is actually launched with telemetry enabled and the project token supplied through runtime configuration.
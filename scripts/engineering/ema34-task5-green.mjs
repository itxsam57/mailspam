import { readFileSync, writeFileSync } from "node:fs";

function replaceExact(text, from, to, label, expectedCount = 1) {
  const count = text.split(from).length - 1;
  if (count !== expectedCount) {
    throw new Error(`${label}: expected ${expectedCount} occurrence(s), found ${count}`);
  }
  return text.split(from).join(to);
}

function edit(path, transform) {
  const before = readFileSync(path, "utf8");
  const after = transform(before);
  if (after === before) throw new Error(`${path}: guarded transform made no change`);
  writeFileSync(path, after);
}

edit("server/src/realtime/realtimeProtectionService.ts", (source) => {
  let next = source;
  next = replaceExact(
    next,
    `export interface RealtimeProtectionStatus {\n  running: boolean;\n  persistentReplayState: boolean;\n  pollIntervalMs: number;\n  queued: number;\n  processing: number;\n  connectedAccounts: number;\n  lastPollAt: number | null;\n  lastSuccessAt: number | null;\n  lastErrorAt: number | null;\n  lastErrorCode: "scan_conflict" | "provider_unavailable" | "provider_mismatch" | "processing_failure" | null;\n}\n`,
    `export interface RealtimeProtectionStatus {\n  running: boolean;\n  persistentReplayState: boolean;\n  pollIntervalMs: number;\n  queued: number;\n  processing: number;\n  connectedAccounts: number;\n  lastPollAt: number | null;\n  lastSuccessAt: number | null;\n  lastErrorAt: number | null;\n  lastErrorCode: "scan_conflict" | "provider_unavailable" | "provider_mismatch" | "processing_failure" | null;\n}\n\nexport interface MailboxReachabilitySnapshot {\n  state: "checking" | "reachable" | "unavailable";\n  checkedAt: number | null;\n  lastReachableAt: number | null;\n}\n\ninterface MailboxReachabilityRecord extends MailboxReachabilitySnapshot {\n  sessionId: string;\n}\n`,
    "reachability public/internal types",
  );

  next = replaceExact(
    next,
    `  #lastErrorAt: number | null = null;\n  #lastErrorCode: RealtimeProtectionStatus["lastErrorCode"] = null;\n`,
    `  #lastErrorAt: number | null = null;\n  #lastErrorCode: RealtimeProtectionStatus["lastErrorCode"] = null;\n  readonly #mailboxReachabilityByAccount = new Map<string, MailboxReachabilityRecord>();\n`,
    "reachability state map",
  );

  next = replaceExact(
    next,
    `  async enqueue(event: CanonicalInboundEventV1): Promise<InboundEventOutcome> {`,
    `  mailboxReachability(session: AccountSession): MailboxReachabilitySnapshot {\n    const record = this.#mailboxReachabilityByAccount.get(session.policyAccountKey);\n    if (!record || record.sessionId !== session.id) {\n      return { state: "checking", checkedAt: null, lastReachableAt: null };\n    }\n    return {\n      state: record.state,\n      checkedAt: record.checkedAt,\n      lastReachableAt: record.lastReachableAt,\n    };\n  }\n\n  #recordMailboxReachability(\n    session: AccountSession,\n    state: "reachable" | "unavailable",\n    checkedAt: number,\n  ): void {\n    const previous = this.#mailboxReachabilityByAccount.get(session.policyAccountKey);\n    const sameSession = previous?.sessionId === session.id;\n    this.#mailboxReachabilityByAccount.set(session.policyAccountKey, {\n      sessionId: session.id,\n      state,\n      checkedAt,\n      lastReachableAt: state === "reachable"\n        ? checkedAt\n        : sameSession ? previous.lastReachableAt : null,\n    });\n  }\n\n  async enqueue(event: CanonicalInboundEventV1): Promise<InboundEventOutcome> {`,
    "reachability public reader",
  );

  next = replaceExact(
    next,
    `  async #pollAccount(session: AccountSession): Promise<void> {`,
    `  async #pollAccount(session: AccountSession, checkedAt: number): Promise<void> {`,
    "poll timestamp parameter",
  );

  next = replaceExact(
    next,
    `    } catch {\n      this.#lastErrorAt = Date.now();\n      this.#lastErrorCode = "provider_unavailable";\n      return;\n    }\n    if (!checkpoint) return;`,
    `    } catch {\n      this.#recordMailboxReachability(session, "unavailable", checkedAt);\n      this.#lastErrorAt = checkedAt;\n      this.#lastErrorCode = "provider_unavailable";\n      return;\n    }\n    this.#recordMailboxReachability(session, "reachable", checkedAt);\n    if (!checkpoint) return;`,
    "probe outcome reachability recording",
  );

  next = replaceExact(
    next,
    `      await Promise.all([...unique.values()].map((session) => this.#pollAccount(session)));`,
    `      await Promise.all([...unique.values()].map((session) => this.#pollAccount(session, now)));`,
    "poll supplied clock wiring",
  );
  return next;
});

edit("server/src/api/server.ts", (source) => {
  let next = source;
  next = replaceExact(
    next,
    `import { ReviewActionConflictError, sessionStore } from "./sessionStore.js";`,
    `import { ReviewActionConflictError, sessionStore, type AccountSession } from "./sessionStore.js";`,
    "AccountSession type import",
  );

  next = replaceExact(
    next,
    `const MAX_CREDENTIAL_VALUE_LENGTH = 16_384;\n`,
    `const MAX_CREDENTIAL_VALUE_LENGTH = 16_384;\n\ntype PublicMailboxReachabilityState = "checking" | "reachable" | "unavailable" | "unknown";\n\ninterface PublicMailboxReachability {\n  state: PublicMailboxReachabilityState;\n  checkedAt: number | null;\n  lastReachableAt: number | null;\n}\n\nfunction publicReachabilityTimestamp(value: unknown): number | null {\n  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;\n}\n\nfunction publicMailboxReachability(\n  session: AccountSession,\n  reader?: (session: AccountSession) => unknown,\n): PublicMailboxReachability {\n  let value: unknown;\n  try { value = reader?.(session); } catch { value = undefined; }\n  if (!value || typeof value !== "object" || Array.isArray(value)) {\n    return { state: "unknown", checkedAt: null, lastReachableAt: null };\n  }\n  const record = value as Record<string, unknown>;\n  const state = record.state === "checking" || record.state === "reachable" || record.state === "unavailable"\n    ? record.state\n    : "unknown";\n  return {\n    state,\n    checkedAt: publicReachabilityTimestamp(record.checkedAt),\n    lastReachableAt: publicReachabilityTimestamp(record.lastReachableAt),\n  };\n}\n`,
    "fixed reachability sanitizer",
  );

  next = replaceExact(
    next,
    `  developerToolsEnabled?: boolean;\n  developerTestSuiteRunner?: typeof runDeveloperTestSuite;`,
    `  developerToolsEnabled?: boolean;\n  developerTestSuiteRunner?: typeof runDeveloperTestSuite;\n  accountReachability?: (session: AccountSession) => unknown;`,
    "server reachability dependency",
  );

  next = replaceExact(
    next,
    `      accountId: session.id,\n      provider: session.provider,\n      label: session.label,\n    })));`,
    `      accountId: session.id,\n      provider: session.provider,\n      label: session.label,\n      reachability: publicMailboxReachability(session, options.accountReachability),\n    })));`,
    "accounts sanitized reachability response",
  );
  return next;
});

edit("server/src/api/localDesktopServer.ts", (source) => {
  let next = source;
  next = replaceExact(
    next,
    `import { sessionStore } from "./sessionStore.js";`,
    `import { sessionStore, type AccountSession } from "./sessionStore.js";`,
    "local desktop AccountSession type import",
  );
  next = replaceExact(
    next,
    `  deviceIdentity?: AccountPlatformRouteDependencies["deviceIdentity"];\n  developmentEntitlementsEnabled?: boolean;`,
    `  deviceIdentity?: AccountPlatformRouteDependencies["deviceIdentity"];\n  developmentEntitlementsEnabled?: boolean;\n  accountReachability?: (session: AccountSession) => unknown;`,
    "local desktop reachability option",
  );
  next = replaceExact(
    next,
    `    fixtureConnections,\n    developerToolsEnabled: developmentEntitlementsEnabled,\n  });`,
    `    fixtureConnections,\n    developerToolsEnabled: developmentEntitlementsEnabled,\n    accountReachability: options.accountReachability,\n  });`,
    "local desktop reachability pass-through",
  );
  return next;
});

edit("server/src/index.ts", (source) => replaceExact(
  source,
  `const app = createConsumerDesktopServer({\n  backgroundProtection,`,
  `const app = createConsumerDesktopServer({\n  accountReachability: (session) => realtimeProtection.mailboxReachability(session),\n  backgroundProtection,`,
  "production reachability wiring",
));

console.log("EMA-34 Task 5 guarded mailbox reachability transform applied.");

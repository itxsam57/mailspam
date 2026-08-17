import { readFileSync, writeFileSync } from "node:fs";

function replaceExactlyOnce(source, oldValue, newValue, label) {
  const first = source.indexOf(oldValue);
  if (first < 0 || source.indexOf(oldValue, first + oldValue.length) >= 0) {
    throw new Error(`Expected exactly one ${label} snippet.`);
  }
  return source.slice(0, first) + newValue + source.slice(first + oldValue.length);
}

const backgroundPath = "server/src/api/backgroundProtection.ts";
let background = readFileSync(backgroundPath, "utf8");
background = replaceExactlyOnce(
  background,
  'sessions?: Pick<SessionStore, "list">;',
  'sessions?: Pick<SessionStore, "canonicalForPolicyAccountKey">;',
  "background options contract",
);
background = replaceExactlyOnce(
  background,
  'private readonly sessions: Pick<SessionStore, "list">;',
  'private readonly sessions: Pick<SessionStore, "canonicalForPolicyAccountKey">;',
  "background member contract",
);
background = replaceExactlyOnce(
  background,
  `    const session = this.sessions.list().find((candidate) => candidate.policyAccountKey === due.accountKey);
    if (!session || session.closing || session.activeScanWorker) {
      this.repository.save(due.accountKey, {
        ...due.record,
        status: "deferred",
        nextRunAt: now + CONFLICT_RETRY_MS,
        lastErrorCode: session?.activeScanWorker ? "scan_conflict" : "provider_unavailable",
      });
      return false;
    }
`,
  `    let session: AccountSession | undefined;
    try {
      session = this.sessions.canonicalForPolicyAccountKey(due.accountKey);
    } catch {
      const consecutiveFailures = Math.min(16, due.record.consecutiveFailures + 1);
      this.repository.save(due.accountKey, {
        ...due.record,
        status: "failed",
        nextRunAt: nextBackgroundRunAt(now, due.record.intervalMinutes, consecutiveFailures),
        lastAttemptAt: now,
        consecutiveFailures,
        lastErrorCode: "protected_state_failure",
      });
      return false;
    }
    if (!session || session.closing || session.activeScanWorker) {
      this.repository.save(due.accountKey, {
        ...due.record,
        status: "deferred",
        nextRunAt: now + CONFLICT_RETRY_MS,
        lastErrorCode: session?.activeScanWorker ? "scan_conflict" : "provider_unavailable",
      });
      return false;
    }
`,
  "background canonical lookup",
);
writeFileSync(backgroundPath, background);

const realtimePath = "server/src/realtime/realtimeProtectionProcessor.ts";
let realtime = readFileSync(realtimePath, "utf8");
const oldType = 'Pick<SessionStore, "list">';
const typeMatches = realtime.split(oldType).length - 1;
if (typeMatches !== 2) throw new Error(`Expected exactly two realtime list contracts, found ${typeMatches}.`);
realtime = realtime.split(oldType).join('Pick<SessionStore, "canonicalForPolicyAccountKey">');
realtime = replaceExactlyOnce(
  realtime,
  `    const candidates = this.sessions.list().filter((session) => session.policyAccountKey === event.accountKey && !session.closing);
    if (candidates.length === 0) {
      throw new RealtimeProtectionRunError("provider_unavailable", "The protected mailbox is not connected locally.");
    }
    const providerMatches = candidates.filter((session) => sessionProvider(session) === event.provider);
    if (providerMatches.length !== 1) {
      throw new RealtimeProtectionRunError(
        "provider_mismatch",
        providerMatches.length === 0
          ? "The inbound provider does not match the connected protected mailbox."
          : "More than one active mailbox session matches the inbound protection identity.",
      );
    }
    const session = providerMatches[0]!;
`,
  `    let session: AccountSession | undefined;
    try {
      session = this.sessions.canonicalForPolicyAccountKey(event.accountKey);
    } catch {
      throw new RealtimeProtectionRunError(
        "provider_mismatch",
        "Mailbox session ownership is ambiguous; reconnect this mailbox before realtime protection continues.",
      );
    }
    if (!session) {
      throw new RealtimeProtectionRunError("provider_unavailable", "The protected mailbox is not connected locally.");
    }
    if (sessionProvider(session) !== event.provider) {
      throw new RealtimeProtectionRunError(
        "provider_mismatch",
        "The inbound provider does not match the connected protected mailbox.",
      );
    }
`,
  "realtime canonical lookup",
);
writeFileSync(realtimePath, realtime);

console.log("Applied guarded Task 3 canonical-owner production edits.");

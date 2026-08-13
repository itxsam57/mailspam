import { createHash } from "node:crypto";
import type { CanonicalEnvelope } from "../canonical/envelope.js";

export interface DigitalAccountFootprintEntry {
  serviceDomain: string;
  evidenceKind: "account_welcome" | "verification" | "password_security" | "receipt_subscription";
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  messages: number;
  authenticatedMessages: number;
  localServiceId: string;
}

export interface DigitalAccountFootprintSnapshot {
  schemaVersion: 1;
  generatedAt: string;
  inspectedMessages: number;
  entries: DigitalAccountFootprintEntry[];
  incomplete: boolean;
  limitations: string[];
  privacy: "local_discovery_no_service_list_upload";
}

const ACCOUNT_PATTERNS: Array<[DigitalAccountFootprintEntry["evidenceKind"], RegExp]> = [
  ["account_welcome", /\b(welcome|account created|thanks for joining|your account|complete your profile)\b/i],
  ["verification", /\b(verify (?:your )?(?:email|account)|confirm (?:your )?email|email verification|activation link)\b/i],
  ["password_security", /\b(password reset|password changed|security alert|new sign[- ]?in|two[- ]?factor|authentication)\b/i],
  ["receipt_subscription", /\b(receipt|subscription|membership|renewal|order confirmation|invoice)\b/i],
];

function authenticationPassed(envelope: CanonicalEnvelope): boolean {
  return envelope.authentication.dmarc === "pass"
    || (envelope.authentication.spf === "pass" && envelope.authentication.dkim === "pass");
}

function timestamp(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function discoverDigitalAccountFootprint(envelopes: readonly CanonicalEnvelope[]): DigitalAccountFootprintSnapshot {
  const bounded = envelopes.slice(0, 500);
  const groups = new Map<string, {
    kind: DigitalAccountFootprintEntry["evidenceKind"];
    messages: number;
    authenticatedMessages: number;
    first: number | null;
    last: number | null;
  }>();

  for (const envelope of bounded) {
    const domain = envelope.from.domain?.trim().toLowerCase();
    if (!domain || envelope.folder === "trash" || envelope.folder === "drafts") continue;
    const content = `${envelope.subject}\n${envelope.textPreview ?? ""}`.slice(0, 8_000);
    const evidence = ACCOUNT_PATTERNS.find(([, pattern]) => pattern.test(content));
    if (!evidence) continue;
    const [kind] = evidence;
    const key = `${domain}\0${kind}`;
    const time = timestamp(envelope.date);
    const group = groups.get(key) ?? { kind, messages: 0, authenticatedMessages: 0, first: null, last: null };
    group.messages += 1;
    if (authenticationPassed(envelope)) group.authenticatedMessages += 1;
    if (time !== null) {
      group.first = group.first === null ? time : Math.min(group.first, time);
      group.last = group.last === null ? time : Math.max(group.last, time);
    }
    groups.set(key, group);
  }

  const entries = [...groups.entries()]
    .filter(([, group]) => group.authenticatedMessages > 0)
    .map(([key, group]): DigitalAccountFootprintEntry => {
      const [serviceDomain] = key.split("\0");
      return {
        serviceDomain: serviceDomain!,
        evidenceKind: group.kind,
        firstObservedAt: group.first === null ? null : new Date(group.first).toISOString(),
        lastObservedAt: group.last === null ? null : new Date(group.last).toISOString(),
        messages: group.messages,
        authenticatedMessages: group.authenticatedMessages,
        localServiceId: createHash("sha256").update(`email-shield-service-v1\n${serviceDomain}`).digest("hex").slice(0, 24),
      };
    })
    .sort((left, right) => right.messages - left.messages)
    .slice(0, 250);

  const limitations: string[] = [
    "This local footprint is inferred only from authenticated account/welcome/security/receipt messages visible in the bounded mailbox sample. It is not a complete registry of every online account you own.",
  ];
  if (envelopes.length > bounded.length) limitations.push("The discovery scan was bounded and did not inspect the entire supplied mailbox sample.");
  if (bounded.some((envelope) => envelope.parseStatus !== "complete" || envelope.diagnostics.contentCoverage === "insufficient")) {
    limitations.push("Some messages were partial or unreadable and were not used as positive account-discovery evidence.");
  }
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    inspectedMessages: bounded.length,
    entries,
    incomplete: limitations.length > 1,
    limitations,
    privacy: "local_discovery_no_service_list_upload",
  };
}

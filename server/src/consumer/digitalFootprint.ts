import { createHash } from "node:crypto";
import type { CanonicalEnvelope } from "../canonical/envelope.js";

export type DigitalAccountEvidenceKind = "account_welcome" | "verification" | "password_security" | "receipt_subscription";

export interface DigitalAccountFootprintEvidence {
  kind: DigitalAccountEvidenceKind;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
  messages: number;
  authenticatedMessages: number;
}

export interface DigitalAccountFootprintEntry {
  serviceDomain: string;
  /** Primary evidence kind retained for schema/backward compatibility. */
  evidenceKind: DigitalAccountEvidenceKind;
  evidence: DigitalAccountFootprintEvidence[];
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

const ACCOUNT_PATTERNS: Array<[DigitalAccountEvidenceKind, RegExp]> = [
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

function isoOrNull(value: number | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}

interface MutableEvidence {
  kind: DigitalAccountEvidenceKind;
  messages: number;
  authenticatedMessages: number;
  first: number | null;
  last: number | null;
}

interface MutableService {
  messages: number;
  authenticatedMessages: number;
  first: number | null;
  last: number | null;
  evidence: Map<DigitalAccountEvidenceKind, MutableEvidence>;
}

function recordTime(target: { first: number | null; last: number | null }, time: number | null): void {
  if (time === null) return;
  target.first = target.first === null ? time : Math.min(target.first, time);
  target.last = target.last === null ? time : Math.max(target.last, time);
}

export function discoverDigitalAccountFootprint(envelopes: readonly CanonicalEnvelope[]): DigitalAccountFootprintSnapshot {
  const bounded = envelopes.slice(0, 500);
  const groups = new Map<string, MutableService>();

  for (const envelope of bounded) {
    const domain = envelope.from.domain?.trim().toLowerCase();
    if (!domain || envelope.folder === "trash" || envelope.folder === "drafts") continue;
    const content = `${envelope.subject}\n${envelope.textPreview ?? ""}`.slice(0, 8_000);
    const matched = ACCOUNT_PATTERNS.find(([, pattern]) => pattern.test(content));
    if (!matched) continue;
    const [kind] = matched;
    const time = timestamp(envelope.date);
    const authenticated = authenticationPassed(envelope);
    const group = groups.get(domain) ?? {
      messages: 0,
      authenticatedMessages: 0,
      first: null,
      last: null,
      evidence: new Map<DigitalAccountEvidenceKind, MutableEvidence>(),
    };
    group.messages += 1;
    if (authenticated) group.authenticatedMessages += 1;
    recordTime(group, time);

    const category = group.evidence.get(kind) ?? {
      kind,
      messages: 0,
      authenticatedMessages: 0,
      first: null,
      last: null,
    };
    category.messages += 1;
    if (authenticated) category.authenticatedMessages += 1;
    recordTime(category, time);
    group.evidence.set(kind, category);
    groups.set(domain, group);
  }

  const entries = [...groups.entries()]
    .filter(([, group]) => group.authenticatedMessages > 0)
    .map(([serviceDomain, group]): DigitalAccountFootprintEntry => {
      const evidence = [...group.evidence.values()]
        .filter((category) => category.authenticatedMessages > 0)
        .sort((left, right) => right.messages - left.messages || left.kind.localeCompare(right.kind))
        .map((category): DigitalAccountFootprintEvidence => ({
          kind: category.kind,
          firstObservedAt: isoOrNull(category.first),
          lastObservedAt: isoOrNull(category.last),
          messages: category.messages,
          authenticatedMessages: category.authenticatedMessages,
        }));
      const primary = evidence[0]!;
      return {
        serviceDomain,
        evidenceKind: primary.kind,
        evidence,
        firstObservedAt: isoOrNull(group.first),
        lastObservedAt: isoOrNull(group.last),
        messages: group.messages,
        authenticatedMessages: group.authenticatedMessages,
        localServiceId: createHash("sha256").update(`email-shield-service-v1\n${serviceDomain}`).digest("hex").slice(0, 24),
      };
    })
    .sort((left, right) => right.messages - left.messages || left.serviceDomain.localeCompare(right.serviceDomain))
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

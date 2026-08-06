import { createHash } from "node:crypto";
import type { CanonicalEnvelope } from "../canonical/envelope.js";
import type { ScoredMessage } from "../engine/verdict.js";
import { organizationalDomain, sameOrganizationalDomain } from "../util/domainRelation.js";
import type { CommunityIndicator, CommunityReportContext } from "./types.js";

const GENERIC_DELIVERY_LOCAL_PART = /^(?:do-?not-?reply|no-?reply|noreply|mailer|mail|notification|notifications|reports?|support|updates?)\b/i;
const SUBJECT_STOP_WORDS = new Set([
  "about", "after", "again", "from", "have", "hello", "here", "into", "just", "message",
  "notification", "please", "re", "report", "sent", "that", "this", "update", "with", "your",
]);

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeDomain(value: string | null | undefined): string | null {
  const normalized = value?.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  return normalized || null;
}

export function externalLinkDomains(envelope: CanonicalEnvelope): string[] {
  const domains = new Set<string>();
  for (const link of envelope.links) {
    try {
      const parsed = new URL(link.normalizedUrl || link.rawUrl);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") continue;
      domains.add(parsed.hostname.toLowerCase().replace(/^www\./, ""));
    } catch {}
  }
  return [...domains].sort();
}

function subjectSkeleton(subject: string): string {
  const tokens = subject
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/\d+/g, "#")
    .replace(/[^a-z#]+/g, " ")
    .split(/\s+/)
    .filter((token) => token.length >= 4 && !SUBJECT_STOP_WORDS.has(token))
    .slice(0, 12);
  return tokens.join(" ");
}

function genericDeliverySender(envelope: CanonicalEnvelope): boolean {
  const localPart = envelope.from.address?.split("@")[0] ?? "";
  return GENERIC_DELIVERY_LOCAL_PART.test(localPart);
}

export function campaignFingerprint(envelope: CanonicalEnvelope): string {
  const senderAddress = envelope.from.address?.trim().toLowerCase() ?? "";
  const senderDomain = normalizeDomain(envelope.from.domain) ?? "";
  const deliveryIdentity = genericDeliverySender(envelope) ? senderDomain : senderAddress;
  const replyDomain = normalizeDomain(envelope.replyTo?.domain) ?? "";
  const linkDomains = externalLinkDomains(envelope);
  const attachmentHashes = envelope.attachments
    .map((attachment) => attachment.sha256?.toLowerCase())
    .filter((value): value is string => Boolean(value))
    .sort();

  return sha256(JSON.stringify({
    version: 1,
    deliveryIdentity,
    replyDomain,
    linkDomains,
    attachmentHashes,
    subjectSkeleton: subjectSkeleton(envelope.subject),
  }));
}

function uniqueIndicators(values: CommunityIndicator[]): CommunityIndicator[] {
  const seen = new Set<string>();
  const output: CommunityIndicator[] = [];
  for (const item of values) {
    const key = `${item.type}\0${item.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push({ type: item.type, value: item.value.toLowerCase() });
  }
  return output;
}

export function buildCommunityReportContext(
  envelope: CanonicalEnvelope,
  scored: ScoredMessage,
): CommunityReportContext {
  const fingerprint = campaignFingerprint(envelope);
  const indicators: CommunityIndicator[] = [{ type: "campaign", value: fingerprint }];
  const senderAddress = envelope.from.address?.trim().toLowerCase() ?? null;
  const senderDomain = normalizeDomain(envelope.from.domain);
  const replyDomain = normalizeDomain(envelope.replyTo?.domain);

  // Generic no-reply/reporting senders are often shared delivery platforms.
  // Do not globally condemn that address; publish the campaign and downstream
  // reply/destination indicators instead.
  if (senderAddress && !genericDeliverySender(envelope)) {
    indicators.push({ type: "sender", value: senderAddress });
  }

  if (
    replyDomain &&
    (!senderDomain || !sameOrganizationalDomain(replyDomain, senderDomain))
  ) {
    indicators.push({ type: "reply_to_domain", value: organizationalDomain(replyDomain) });
  }

  for (const domain of externalLinkDomains(envelope)) {
    if (!senderDomain || !sameOrganizationalDomain(domain, senderDomain)) {
      indicators.push({ type: "url_domain", value: organizationalDomain(domain) });
    }
  }

  for (const hash of envelope.attachments
    .map((attachment) => attachment.sha256?.toLowerCase())
    .filter((value): value is string => Boolean(value))) {
    indicators.push({ type: "attachment_hash", value: hash });
  }

  const evidence = scored.evidence.filter((item) => item.source !== "personal_rule" && item.source !== "signed_feed");
  return {
    campaignFingerprint: fingerprint,
    indicators: uniqueIndicators(indicators),
    evidenceCodes: [...new Set(evidence.map((item) => item.code))].sort(),
    evidenceScore: Math.max(0, evidence.reduce((sum, item) => sum + Math.max(0, item.scoreContribution), 0)),
    verdict: scored.verdict,
  };
}

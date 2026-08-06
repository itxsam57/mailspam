import { createHash } from "node:crypto";
import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { isSharedMailboxDomain } from "../engine/identitySignals.js";
import type { ScoredMessage } from "../engine/verdict.js";
import { organizationalDomain, sameOrganizationalDomain } from "../util/domainRelation.js";
import type { CommunityIndicator, CommunityReportContext } from "./types.js";

const GENERIC_DELIVERY_TOKEN = /(?:^|[-_.+])(?:do[-_.]?not[-_.]?reply|no[-_.]?reply|noreply|mailer|mail|notification|notifications|report|reports|support|update|updates)(?:$|[-_.+])/i;
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
  const localPart = envelope.from.address?.split("@")[0]?.trim().toLowerCase() ?? "";
  return GENERIC_DELIVERY_TOKEN.test(localPart);
}

export function campaignFingerprint(envelope: CanonicalEnvelope): string {
  const senderDomain = normalizeDomain(envelope.from.domain) ?? "";
  const replyDomain = normalizeDomain(envelope.replyTo?.domain) ?? "";
  const linkDomains = externalLinkDomains(envelope).map(organizationalDomain).filter(Boolean).sort();
  const attachmentHashes = envelope.attachments
    .map((attachment) => attachment.sha256?.toLowerCase())
    .filter((value): value is string => Boolean(value))
    .sort();
  const hasDownstreamIdentity = Boolean(replyDomain || linkDomains.length || attachmentHashes.length);

  return sha256(JSON.stringify({
    version: 2,
    // Stable downstream infrastructure identifies a campaign more reliably
    // than its disposable delivery sender. Use the sender organization only
    // when no Reply-To, destination or attachment signal exists.
    fallbackSenderDomain: hasDownstreamIdentity ? "" : organizationalDomain(senderDomain),
    replyDomain: replyDomain ? organizationalDomain(replyDomain) : "",
    linkDomains,
    attachmentHashes,
    subjectSkeleton: subjectSkeleton(envelope.subject),
  }));
}

function uniqueIndicators(values: CommunityIndicator[]): CommunityIndicator[] {
  const seen = new Set<string>();
  const output: CommunityIndicator[] = [];
  for (const item of values) {
    const normalizedValue = item.value.toLowerCase();
    if (!normalizedValue) continue;
    const key = `${item.type}\0${normalizedValue}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push({ type: item.type, value: normalizedValue });
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
  const evidence = scored.evidence.filter((item) => item.source !== "personal_rule" && item.source !== "signed_feed");
  const evidenceCodes = new Set(evidence.map((item) => item.code));

  // Generic no-reply/reporting addresses frequently belong to shared delivery
  // platforms. Product-prefixed forms such as "looker-studio-noreply" remain
  // generic and must never become globally malicious exact-sender indicators.
  if (senderAddress && !genericDeliverySender(envelope)) {
    indicators.push({ type: "sender", value: senderAddress });
  }

  // A shared consumer mailbox provider authenticates the mailbox service, not
  // a malicious organization. Keep the campaign fingerprint, but do not turn
  // gmail.com, outlook.com, yahoo.com, etc. into globally blocked domains.
  if (
    replyDomain &&
    !isSharedMailboxDomain(replyDomain) &&
    (!senderDomain || !sameOrganizationalDomain(replyDomain, senderDomain))
  ) {
    indicators.push({ type: "reply_to_domain", value: organizationalDomain(replyDomain) });
  }

  // URL shorteners are broad shared infrastructure. The campaign fingerprint
  // can still aggregate independent reports, but the shortener's whole domain
  // must not be published as malicious merely because one campaign used it.
  const sharedShortenerDetected = evidenceCodes.has("URL_SHORTENER");
  if (!sharedShortenerDetected) {
    for (const domain of externalLinkDomains(envelope)) {
      if (!senderDomain || !sameOrganizationalDomain(domain, senderDomain)) {
        indicators.push({ type: "url_domain", value: organizationalDomain(domain) });
      }
    }
  }

  for (const hash of envelope.attachments
    .map((attachment) => attachment.sha256?.toLowerCase())
    .filter((value): value is string => Boolean(value))) {
    indicators.push({ type: "attachment_hash", value: hash });
  }

  return {
    campaignFingerprint: fingerprint,
    indicators: uniqueIndicators(indicators),
    evidenceCodes: [...evidenceCodes].sort(),
    evidenceScore: Math.max(0, evidence.reduce((sum, item) => sum + Math.max(0, item.scoreContribution), 0)),
    verdict: scored.verdict,
  };
}

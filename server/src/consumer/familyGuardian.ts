import { createHash, randomUUID } from "node:crypto";
import type { SignedFeedEntry, SignedThreatIndicatorEntry } from "../engine/layers/globalIntelligence.js";
import type { PublicAccountPlatformSnapshot } from "../platform/accountFamilyTypes.js";

export type ScamRiskCategory =
  | "banking"
  | "crypto_investment"
  | "gift_card"
  | "government_legal"
  | "delivery_payment"
  | "romance"
  | "job_task"
  | "remote_access_support"
  | "account_takeover"
  | "shopping"
  | "other";

export const SCAM_RISK_CATEGORIES: readonly ScamRiskCategory[] = Object.freeze([
  "banking",
  "crypto_investment",
  "gift_card",
  "government_legal",
  "delivery_payment",
  "romance",
  "job_task",
  "remote_access_support",
  "account_takeover",
  "shopping",
  "other",
]);

const CATEGORY_PATTERNS: Readonly<Record<Exclude<ScamRiskCategory, "other">, readonly RegExp[]>> = Object.freeze({
  banking: [/\b(bank|wire transfer|bank transfer|routing number|account number|swift|iban|payment verification)\b/i],
  crypto_investment: [/\b(crypto|bitcoin|ethereum|wallet|seed phrase|investment return|trading profit|liquidity)\b/i],
  gift_card: [/\b(gift\s*card|itunes card|steam card|google play card|voucher code)\b/i],
  government_legal: [/\b(tax authority|police|court|warrant|fine|immigration|customs|government fee|legal action)\b/i],
  delivery_payment: [/\b(parcel|delivery|courier|shipping fee|redelivery|customs fee|delivery payment)\b/i],
  romance: [/\b(love you|soulmate|relationship|widowed|military deployment|emergency travel|romance)\b/i],
  job_task: [/\b(job offer|recruiter|task job|work from home|remote job|training fee|commission task|optimization task)\b/i],
  remote_access_support: [/\b(anydesk|teamviewer|quick assist|remote desktop|remote support|screen share|support agent|refund department)\b/i],
  account_takeover: [/\b(password reset|security alert|unusual sign[- ]?in|verify your account|account suspended|authentication code|one[- ]time code|otp)\b/i],
  shopping: [/\b(order confirmation|storefront|limited stock|flash sale|payment failed|marketplace seller|purchase protection)\b/i],
});

export function classifyScamRiskCategories(text: string): ScamRiskCategory[] {
  const bounded = String(text ?? "").slice(0, 24_000);
  const matched = (Object.entries(CATEGORY_PATTERNS) as Array<[Exclude<ScamRiskCategory, "other">, readonly RegExp[]]>)
    .filter(([, patterns]) => patterns.some((pattern) => pattern.test(bounded)))
    .map(([category]) => category);
  return matched.length ? matched : ["other"];
}

export interface FamilyActivitySummary {
  available: boolean;
  familyCircleId: string | null;
  membersProtected: number;
  seatLimit: number;
  strictProtection: boolean;
  warningCampaigns: number;
  confirmedCampaigns: number;
  pendingInvites: number;
  privacy: "aggregate_only_no_member_mailbox_content";
}

export function familyActivitySummary(snapshot: PublicAccountPlatformSnapshot): FamilyActivitySummary {
  if (!snapshot.family) {
    return {
      available: false,
      familyCircleId: null,
      membersProtected: 0,
      seatLimit: 0,
      strictProtection: false,
      warningCampaigns: 0,
      confirmedCampaigns: 0,
      pendingInvites: 0,
      privacy: "aggregate_only_no_member_mailbox_content",
    };
  }
  return {
    available: true,
    familyCircleId: snapshot.family.familyCircleId,
    membersProtected: snapshot.family.seatsUsed,
    seatLimit: snapshot.family.seatLimit,
    strictProtection: snapshot.family.strictProtection,
    warningCampaigns: snapshot.family.warningCampaigns,
    confirmedCampaigns: snapshot.family.confirmedCampaigns,
    pendingInvites: snapshot.family.pendingInvites,
    privacy: "aggregate_only_no_member_mailbox_content",
  };
}

export interface TrustedAssistancePacketV1 {
  schemaVersion: 1;
  packetId: string;
  createdAt: string;
  expiresAt: string;
  verdict: "review" | "high_risk" | "confirmed_threat" | "unknown";
  categories: ScamRiskCategory[];
  strongestSignals: string[];
  safeNextAction: string;
  userNote: string | null;
  /** Included only when the user explicitly opts in to sharing an excerpt. */
  consentedExcerpt: string | null;
  itemFingerprint: string;
  privacy: "explicit_single_item_share_not_mailbox_access";
}

export function createTrustedAssistancePacket(input: {
  verdict: TrustedAssistancePacketV1["verdict"];
  textForCategory: string;
  strongestSignals: readonly string[];
  safeNextAction: string;
  userNote?: string | null;
  excerpt?: string | null;
  shareExcerpt: boolean;
  now?: number;
}): TrustedAssistancePacketV1 {
  const now = input.now ?? Date.now();
  const excerpt = input.shareExcerpt && input.excerpt ? input.excerpt.trim().slice(0, 800) : null;
  const userNote = input.userNote?.trim().slice(0, 280) || null;
  const strongestSignals = [...new Set(input.strongestSignals.map((item) => item.trim()).filter(Boolean))].slice(0, 6);
  const fingerprintSource = [input.verdict, input.textForCategory.slice(0, 8_000), strongestSignals.join("\n")].join("\n");
  return {
    schemaVersion: 1,
    packetId: `assist_${randomUUID()}`,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 24 * 60 * 60 * 1_000).toISOString(),
    verdict: input.verdict,
    categories: classifyScamRiskCategories(input.textForCategory),
    strongestSignals,
    safeNextAction: input.safeNextAction.trim().slice(0, 500),
    userNote,
    consentedExcerpt: excerpt,
    itemFingerprint: createHash("sha256").update(fingerprintSource, "utf8").digest("hex"),
    privacy: "explicit_single_item_share_not_mailbox_access",
  };
}

export interface CampaignAdvisory {
  ruleId: string;
  indicatorType: SignedThreatIndicatorEntry["type"];
  independentReports: number;
  firstSeen: string | null;
  lastSeen: string | null;
  severity: "watch" | "warning" | "confirmed";
  guidance: string;
}

function threatEntries(entries: readonly SignedFeedEntry[] | null): SignedThreatIndicatorEntry[] | null {
  if (entries === null) return null;
  return entries.filter((entry): entry is SignedThreatIndicatorEntry => entry.type !== "identity");
}

/**
 * Privacy-safe radar derived only from already verified signed intelligence.
 * It never reconstructs examples from private messages and never accepts raw
 * reporter location. Region is deliberately a future signed-feed attribute;
 * until that exists, the UI must label advisories as network-wide.
 */
export function campaignRadar(entries: readonly SignedFeedEntry[] | null): {
  available: boolean;
  scope: "network_wide";
  advisories: CampaignAdvisory[];
  reason: string | null;
} {
  const threats = threatEntries(entries);
  if (threats === null) {
    return {
      available: false,
      scope: "network_wide",
      advisories: [],
      reason: "Signed campaign intelligence is unavailable or failed verification; no advisory was treated as safe.",
    };
  }
  const advisories = threats
    .filter((entry) => entry.type === "campaign" && (entry.independentReports ?? 0) >= 2)
    .sort((left, right) => (right.independentReports ?? 0) - (left.independentReports ?? 0))
    .slice(0, 20)
    .map((entry): CampaignAdvisory => {
      const independentReports = entry.independentReports ?? 0;
      const severity = entry.confirmedThreat ? "confirmed" : independentReports >= 3 ? "warning" : "watch";
      return {
        ruleId: entry.ruleId,
        indicatorType: entry.type,
        independentReports,
        firstSeen: entry.firstSeen ?? null,
        lastSeen: entry.lastSeen ?? null,
        severity,
        guidance: entry.confirmedThreat
          ? "A verified scam campaign is active. Do not use contact details or payment instructions from the suspicious message; verify through an independently obtained official channel."
          : "Multiple independent reports describe a similar campaign. Treat matching requests cautiously and verify using an independently obtained official channel.",
      };
    });
  return { available: true, scope: "network_wide", advisories, reason: null };
}

import type { Verdict } from "../engine/verdict.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";

export type CommunityIndicatorType =
  | "sender"
  | "reply_to_domain"
  | "url_domain"
  | "attachment_hash"
  | "campaign";

export interface CommunityIndicator {
  type: CommunityIndicatorType;
  value: string;
}

/**
 * Produced inside the scan worker and kept server-side behind an opaque token.
 * It contains no mailbox address, body, subject, provider message ID, raw URL,
 * contact, credential, OAuth token, or attachment content.
 */
export interface CommunityReportContext {
  campaignFingerprint: string;
  indicators: CommunityIndicator[];
  evidenceCodes: string[];
  evidenceScore: number;
  verdict: Verdict;
}

/** Stable pseudonym derived locally from an account proof and random install key. */
export interface CommunityReportSubmission extends CommunityReportContext {
  schemaVersion: 1;
  reporterProof: string;
  reportedAt: string;
}

export type CommunityCampaignStatus = "candidate" | "warning" | "confirmed";
export type CommunityReportDelivery = "embedded_local" | "remote_shared" | "queued_remote";

export interface CommunityReportReceipt {
  accepted: boolean;
  duplicate: boolean;
  queued: boolean;
  campaignFingerprint: string;
  independentReporters: number;
  status: CommunityCampaignStatus;
  feedUpdated: boolean;
  /** Added by the client-facing submission layer; central aggregate receipts omit it. */
  delivery?: CommunityReportDelivery;
}

export interface CommunityFeedPayload {
  version: 1;
  generatedAt: string;
  expiresAt: string;
  entries: SignedFeedEntry[];
}

export interface SignedCommunityFeed {
  version: 1;
  payload: CommunityFeedPayload;
  signature: {
    algorithm: "Ed25519";
    keyId: string;
    value: string;
  };
}

import type { CommunityIndicator, CommunityReportSubmission } from "./types.js";

const REPORT_VERDICTS = new Set(["safe", "unknown", "review", "high_risk", "confirmed_threat"]);
const INDICATOR_TYPES = new Set(["sender", "reply_to_domain", "url_domain", "attachment_hash", "campaign"]);
const REVIEW_STATUSES = new Set(["candidate", "approved", "rejected"]);
const REPORTER_PROOF_RE = /^[a-f0-9]{64}$/;
const CAMPAIGN_FINGERPRINT_RE = /^[a-f0-9]{64}$/;
const EVIDENCE_CODE_RE = /^[A-Z0-9_]{2,80}$/;
const REVIEWER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{1,79}$/;
const MAX_INDICATOR_VALUE_CHARS = 512;
const MAX_TIMESTAMP_CHARS = 64;
const MAX_EVIDENCE_CODES = 64;
const MAX_INDICATORS = 32;
const MAX_REVIEW_REASON_CHARS = 500;
const MAX_REPUTATION_CASES = 1_000_000_000;

export interface StoredCommunityReporterRecordV1 {
  reportedAt: string;
  evidenceScore: number;
  verdict: CommunityReportSubmission["verdict"];
}

export interface StoredCommunityCampaignRecordV1 {
  firstSeen: string;
  lastSeen: string;
  reporters: Record<string, StoredCommunityReporterRecordV1>;
  indicatorReporters: Record<string, string[]>;
  evidenceCodes: Record<string, number>;
}

export interface StoredCommunityDatabaseV1 {
  version: 1;
  campaigns: Record<string, StoredCommunityCampaignRecordV1>;
}

export interface StoredCommunityReporterRecord {
  reportedAt: string;
  evidenceScore: number;
  verdict: CommunityReportSubmission["verdict"];
  evidenceCodes: string[];
  indicators: CommunityIndicator[];
}

interface StoredCommunityCampaignRecordV2 {
  firstSeen: string;
  lastSeen: string;
  reporters: Record<string, StoredCommunityReporterRecord>;
}

interface StoredCommunityDatabaseV2 {
  version: 2;
  campaigns: Record<string, StoredCommunityCampaignRecordV2>;
}

export type StoredCommunityReviewStatus = "candidate" | "approved" | "rejected";

export interface StoredCommunityReviewRecord {
  status: StoredCommunityReviewStatus;
  createdAt: string;
  resolvedAt: string | null;
  reviewerId: string | null;
  reason: string | null;
}

export interface StoredCommunityReporterReputation {
  resolvedCases: number;
  alignedCases: number;
}

export interface StoredCommunityCampaignRecord {
  firstSeen: string;
  lastSeen: string;
  reporters: Record<string, StoredCommunityReporterRecord>;
  review: StoredCommunityReviewRecord | null;
}

export interface StoredCommunityDatabase {
  version: 3;
  campaigns: Record<string, StoredCommunityCampaignRecord>;
  reporterReputation: Record<string, StoredCommunityReporterReputation>;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const accepted = new Set(allowed);
  return Object.keys(value).every((key) => accepted.has(key));
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_TIMESTAMP_CHARS) return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function parseIndicatorKey(key: string): CommunityIndicator | null {
  const separator = key.indexOf("\0");
  if (separator <= 0) return null;
  const type = key.slice(0, separator);
  const value = key.slice(separator + 1);
  if (!INDICATOR_TYPES.has(type) || !value || value.length > MAX_INDICATOR_VALUE_CHARS) return null;
  if (value !== value.trim().toLowerCase()) return null;
  return { type: type as CommunityIndicator["type"], value };
}

function validEvidenceCodes(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= MAX_EVIDENCE_CODES && value.every((code, index) =>
    typeof code === "string" && EVIDENCE_CODE_RE.test(code) && value.indexOf(code) === index,
  );
}

function validIndicators(value: unknown, fingerprint: string): value is CommunityIndicator[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_INDICATORS) return false;
  const keys = new Set<string>();
  let hasCampaign = false;
  for (const item of value) {
    const candidate = record(item);
    if (!candidate || !onlyKeys(candidate, ["type", "value"])) return false;
    if (typeof candidate.type !== "string" || typeof candidate.value !== "string") return false;
    const indicator = parseIndicatorKey(`${candidate.type}\0${candidate.value}`);
    if (!indicator) return false;
    const key = `${indicator.type}\0${indicator.value}`;
    if (keys.has(key)) return false;
    keys.add(key);
    if (indicator.type === "campaign" && indicator.value === fingerprint) hasCampaign = true;
  }
  return hasCampaign;
}

function validateReporterRecordV1(
  value: unknown,
  campaignFirstSeen: number,
  campaignLastSeen: number,
): StoredCommunityReporterRecordV1 | null {
  const item = record(value);
  if (!item || !onlyKeys(item, ["reportedAt", "evidenceScore", "verdict"])) return null;
  if (!canonicalTimestamp(item.reportedAt)) return null;
  const reportedAt = Date.parse(item.reportedAt);
  if (reportedAt < campaignFirstSeen || reportedAt > campaignLastSeen) return null;
  if (!Number.isInteger(item.evidenceScore) || (item.evidenceScore as number) < 0 || (item.evidenceScore as number) > 20) return null;
  if (typeof item.verdict !== "string" || !REPORT_VERDICTS.has(item.verdict)) return null;
  return item as unknown as StoredCommunityReporterRecordV1;
}

function validateCampaignV1(
  fingerprint: string,
  value: unknown,
): StoredCommunityCampaignRecordV1 | null {
  if (!CAMPAIGN_FINGERPRINT_RE.test(fingerprint)) return null;
  const campaign = record(value);
  if (!campaign || !onlyKeys(campaign, ["firstSeen", "lastSeen", "reporters", "indicatorReporters", "evidenceCodes"])) return null;
  if (!canonicalTimestamp(campaign.firstSeen) || !canonicalTimestamp(campaign.lastSeen)) return null;
  const firstSeen = Date.parse(campaign.firstSeen);
  const lastSeen = Date.parse(campaign.lastSeen);
  if (firstSeen > lastSeen) return null;

  const reporters = record(campaign.reporters);
  if (!reporters) return null;
  const reporterProofs = Object.keys(reporters);
  if (reporterProofs.length === 0) return null;
  const reporterSet = new Set<string>();
  let hasLastSeenReporter = false;
  for (const reporterProof of reporterProofs) {
    if (!REPORTER_PROOF_RE.test(reporterProof) || reporterSet.has(reporterProof)) return null;
    const reporter = validateReporterRecordV1(reporters[reporterProof], firstSeen, lastSeen);
    if (!reporter) return null;
    reporterSet.add(reporterProof);
    if (reporter.reportedAt === campaign.lastSeen) hasLastSeenReporter = true;
  }
  if (!hasLastSeenReporter) return null;

  const indicatorReporters = record(campaign.indicatorReporters);
  if (!indicatorReporters) return null;
  const indicatorKeys = Object.keys(indicatorReporters);
  if (indicatorKeys.length === 0) return null;
  for (const key of indicatorKeys) {
    const indicator = parseIndicatorKey(key);
    if (!indicator) return null;
    if (indicator.type === "campaign" && indicator.value !== fingerprint) return null;
    const support = indicatorReporters[key];
    if (!Array.isArray(support) || support.length === 0 || support.length > reporterProofs.length) return null;
    const sorted = [...support].sort();
    if (sorted.some((proof, index) => proof !== support[index])) return null;
    const unique = new Set<string>();
    for (const proof of support) {
      if (typeof proof !== "string" || !REPORTER_PROOF_RE.test(proof) || !reporterSet.has(proof) || unique.has(proof)) return null;
      unique.add(proof);
    }
  }

  const campaignSupport = indicatorReporters[`campaign\0${fingerprint}`];
  if (!Array.isArray(campaignSupport) || campaignSupport.length !== reporterProofs.length) return null;
  const allReporters = [...reporterProofs].sort();
  if (campaignSupport.some((proof, index) => proof !== allReporters[index])) return null;

  const evidenceCodes = record(campaign.evidenceCodes);
  if (!evidenceCodes) return null;
  for (const [code, count] of Object.entries(evidenceCodes)) {
    if (!EVIDENCE_CODE_RE.test(code) || !Number.isInteger(count) || (count as number) < 1 || (count as number) > reporterProofs.length) return null;
  }

  return campaign as unknown as StoredCommunityCampaignRecordV1;
}

function validateReporterRecord(
  fingerprint: string,
  value: unknown,
  campaignFirstSeen: number,
  campaignLastSeen: number,
): StoredCommunityReporterRecord | null {
  const item = record(value);
  if (!item || !onlyKeys(item, ["reportedAt", "evidenceScore", "verdict", "evidenceCodes", "indicators"])) return null;
  if (!canonicalTimestamp(item.reportedAt)) return null;
  const reportedAt = Date.parse(item.reportedAt);
  if (reportedAt < campaignFirstSeen || reportedAt > campaignLastSeen) return null;
  if (!Number.isInteger(item.evidenceScore) || (item.evidenceScore as number) < 0 || (item.evidenceScore as number) > 20) return null;
  if (typeof item.verdict !== "string" || !REPORT_VERDICTS.has(item.verdict)) return null;
  if (!validEvidenceCodes(item.evidenceCodes) || !validIndicators(item.indicators, fingerprint)) return null;
  return item as unknown as StoredCommunityReporterRecord;
}

function validateCampaignV2(fingerprint: string, value: unknown): StoredCommunityCampaignRecordV2 | null {
  if (!CAMPAIGN_FINGERPRINT_RE.test(fingerprint)) return null;
  const campaign = record(value);
  if (!campaign || !onlyKeys(campaign, ["firstSeen", "lastSeen", "reporters"])) return null;
  if (!canonicalTimestamp(campaign.firstSeen) || !canonicalTimestamp(campaign.lastSeen)) return null;
  const firstSeen = Date.parse(campaign.firstSeen);
  const lastSeen = Date.parse(campaign.lastSeen);
  if (firstSeen > lastSeen) return null;
  const reporters = record(campaign.reporters);
  if (!reporters || Object.keys(reporters).length === 0) return null;
  let observedFirst = Number.POSITIVE_INFINITY;
  let observedLast = 0;
  for (const [proof, rawReporter] of Object.entries(reporters)) {
    if (!REPORTER_PROOF_RE.test(proof)) return null;
    const reporter = validateReporterRecord(fingerprint, rawReporter, firstSeen, lastSeen);
    if (!reporter) return null;
    const timestamp = Date.parse(reporter.reportedAt);
    observedFirst = Math.min(observedFirst, timestamp);
    observedLast = Math.max(observedLast, timestamp);
  }
  if (new Date(observedFirst).toISOString() !== campaign.firstSeen || new Date(observedLast).toISOString() !== campaign.lastSeen) return null;
  return campaign as unknown as StoredCommunityCampaignRecordV2;
}

function validateReview(value: unknown): StoredCommunityReviewRecord | null | undefined {
  if (value === null) return null;
  const review = record(value);
  if (!review || !onlyKeys(review, ["status", "createdAt", "resolvedAt", "reviewerId", "reason"])) return undefined;
  if (typeof review.status !== "string" || !REVIEW_STATUSES.has(review.status)) return undefined;
  // Review timestamps are audit history, not live-evidence timestamps. The
  // evidence retention window may advance campaign.firstSeen after review.
  if (!canonicalTimestamp(review.createdAt)) return undefined;
  if (review.status === "candidate") {
    if (review.resolvedAt !== null || review.reviewerId !== null || review.reason !== null) return undefined;
  } else {
    if (!canonicalTimestamp(review.resolvedAt) || Date.parse(review.resolvedAt) < Date.parse(review.createdAt)) return undefined;
    if (typeof review.reviewerId !== "string" || !REVIEWER_ID_RE.test(review.reviewerId)) return undefined;
    if (typeof review.reason !== "string" || review.reason !== review.reason.trim() || review.reason.length === 0 || review.reason.length > MAX_REVIEW_REASON_CHARS || /[\u0000-\u001f\u007f]/.test(review.reason)) return undefined;
  }
  return review as unknown as StoredCommunityReviewRecord;
}

function validateCampaign(fingerprint: string, value: unknown): StoredCommunityCampaignRecord | null {
  if (!CAMPAIGN_FINGERPRINT_RE.test(fingerprint)) return null;
  const campaign = record(value);
  if (!campaign || !onlyKeys(campaign, ["firstSeen", "lastSeen", "reporters", "review"])) return null;
  if (!canonicalTimestamp(campaign.firstSeen) || !canonicalTimestamp(campaign.lastSeen)) return null;
  const firstSeen = Date.parse(campaign.firstSeen);
  const lastSeen = Date.parse(campaign.lastSeen);
  if (firstSeen > lastSeen) return null;
  const reporters = record(campaign.reporters);
  if (!reporters || Object.keys(reporters).length === 0) return null;
  let observedFirst = Number.POSITIVE_INFINITY;
  let observedLast = 0;
  for (const [proof, rawReporter] of Object.entries(reporters)) {
    if (!REPORTER_PROOF_RE.test(proof)) return null;
    const reporter = validateReporterRecord(fingerprint, rawReporter, firstSeen, lastSeen);
    if (!reporter) return null;
    const timestamp = Date.parse(reporter.reportedAt);
    observedFirst = Math.min(observedFirst, timestamp);
    observedLast = Math.max(observedLast, timestamp);
  }
  if (new Date(observedFirst).toISOString() !== campaign.firstSeen || new Date(observedLast).toISOString() !== campaign.lastSeen) return null;
  const review = validateReview(campaign.review);
  if (review === undefined) return null;
  return { ...campaign, review } as unknown as StoredCommunityCampaignRecord;
}

function validateReputation(value: unknown): Record<string, StoredCommunityReporterReputation> | null {
  const reputation = record(value);
  if (!reputation) return null;
  for (const [proof, raw] of Object.entries(reputation)) {
    if (!REPORTER_PROOF_RE.test(proof)) return null;
    const item = record(raw);
    if (!item || !onlyKeys(item, ["resolvedCases", "alignedCases"])) return null;
    if (!Number.isInteger(item.resolvedCases) || (item.resolvedCases as number) < 1 || (item.resolvedCases as number) > MAX_REPUTATION_CASES) return null;
    if (!Number.isInteger(item.alignedCases) || (item.alignedCases as number) < 0 || (item.alignedCases as number) > (item.resolvedCases as number)) return null;
  }
  return reputation as unknown as Record<string, StoredCommunityReporterReputation>;
}

function validateV1(value: Record<string, unknown>, maxCampaigns: number): StoredCommunityDatabaseV1 {
  const campaigns = record(value.campaigns);
  if (!campaigns || Object.keys(campaigns).length > maxCampaigns) throw new Error("Community aggregate campaign collection is invalid.");
  for (const [fingerprint, campaign] of Object.entries(campaigns)) {
    if (!validateCampaignV1(fingerprint, campaign)) throw new Error("Community aggregate campaign state is invalid.");
  }
  return value as unknown as StoredCommunityDatabaseV1;
}

function validateV2(value: Record<string, unknown>, maxCampaigns: number): StoredCommunityDatabaseV2 {
  const campaigns = record(value.campaigns);
  if (!campaigns || Object.keys(campaigns).length > maxCampaigns) throw new Error("Community aggregate campaign collection is invalid.");
  for (const [fingerprint, campaign] of Object.entries(campaigns)) {
    if (!validateCampaignV2(fingerprint, campaign)) throw new Error("Community aggregate campaign state is invalid.");
  }
  return value as unknown as StoredCommunityDatabaseV2;
}

function validateV3(value: Record<string, unknown>, maxCampaigns: number): StoredCommunityDatabase {
  const campaigns = record(value.campaigns);
  if (!campaigns || Object.keys(campaigns).length > maxCampaigns) throw new Error("Community aggregate campaign collection is invalid.");
  for (const [fingerprint, campaign] of Object.entries(campaigns)) {
    if (!validateCampaign(fingerprint, campaign)) throw new Error("Community aggregate campaign state is invalid.");
  }
  const reporterReputation = validateReputation(value.reporterReputation);
  if (!reporterReputation) throw new Error("Community reporter reputation state is invalid.");
  return { version: 3, campaigns: campaigns as unknown as Record<string, StoredCommunityCampaignRecord>, reporterReputation };
}

function migrateV1(database: StoredCommunityDatabaseV1): StoredCommunityDatabaseV2 {
  const campaigns: Record<string, StoredCommunityCampaignRecordV2> = {};
  for (const [fingerprint, campaign] of Object.entries(database.campaigns)) {
    const proofs = Object.keys(campaign.reporters).sort();
    const reporters: Record<string, StoredCommunityReporterRecord> = {};
    for (const proof of proofs) {
      const prior = campaign.reporters[proof]!;
      const indicators = Object.entries(campaign.indicatorReporters)
        .filter(([, supporters]) => supporters.includes(proof))
        .map(([key]) => parseIndicatorKey(key))
        .filter((item): item is CommunityIndicator => item !== null);
      const evidenceCodes = Object.entries(campaign.evidenceCodes)
        .filter(([, count]) => proofs.indexOf(proof) < count)
        .map(([code]) => code)
        .sort();
      reporters[proof] = { ...prior, evidenceCodes, indicators };
    }
    campaigns[fingerprint] = {
      firstSeen: campaign.firstSeen,
      lastSeen: campaign.lastSeen,
      reporters,
    };
  }
  return { version: 2, campaigns };
}

function migrateV2(database: StoredCommunityDatabaseV2): StoredCommunityDatabase {
  return {
    version: 3,
    campaigns: Object.fromEntries(Object.entries(database.campaigns).map(([fingerprint, campaign]) => [
      fingerprint,
      { ...campaign, review: null },
    ])),
    reporterReputation: {},
  };
}

export function validateStoredCommunityDatabase(value: unknown, maxCampaigns: number): StoredCommunityDatabase {
  const database = record(value);
  if (!database) throw new Error("Community aggregate database shape is invalid.");
  if (database.version === 1) {
    if (!onlyKeys(database, ["version", "campaigns"])) throw new Error("Community aggregate database shape is invalid.");
    return migrateV2(migrateV1(validateV1(database, maxCampaigns)));
  }
  if (database.version === 2) {
    if (!onlyKeys(database, ["version", "campaigns"])) throw new Error("Community aggregate database shape is invalid.");
    return migrateV2(validateV2(database, maxCampaigns));
  }
  if (database.version === 3) {
    if (!onlyKeys(database, ["version", "campaigns", "reporterReputation"])) throw new Error("Community aggregate database shape is invalid.");
    return validateV3(database, maxCampaigns);
  }
  throw new Error("Community aggregate database shape is invalid.");
}

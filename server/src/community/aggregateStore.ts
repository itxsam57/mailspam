import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  writeSync,
  writeFileSync,
} from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { join } from "node:path";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import { readBoundedRegularFile, readBoundedUtf8File, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import {
  validateStoredCommunityDatabase,
  type StoredCommunityCampaignRecord,
  type StoredCommunityDatabase,
  type StoredCommunityReporterRecord,
  type StoredCommunityReporterReputation,
  type StoredCommunityReviewRecord,
} from "./aggregateState.js";
import { CommunityReportCapacityError, CommunityReportRateLimitError, CommunityReportValidationError } from "./errors.js";
import {
  hasBlockFeedback,
  hasExplicitScamFeedback,
  hasLegitimateFeedback,
  LEGITIMATE_CONSENSUS_REPORTERS,
  LEGITIMATE_RULE_PREFIX,
} from "./feedback.js";
import {
  COMMUNITY_STORAGE_KEY_BYTES,
  MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES,
  MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
} from "./resourceLimits.js";
import { COMMUNITY_REPORT_DATABASE_FILE, COMMUNITY_REPORT_JOURNAL_FILE } from "./storageFiles.js";
import type {
  CommunityCampaignStatus,
  CommunityFeedPayload,
  CommunityIndicator,
  CommunityReportReceipt,
  CommunityReportSubmission,
} from "./types.js";

const ALGORITHM = "aes-256-gcm";
const SNAPSHOT_AAD = Buffer.from("email-shield-community-reports-v1", "utf8");
const JOURNAL_AAD = Buffer.from("email-shield-community-report-journal-v1", "utf8");
const MAX_REPORTS_PER_REPORTER_PER_DAY = 50;
const MAX_CAMPAIGNS = 100_000;
const MAX_INDICATORS_PER_REPORT = 32;
const MAX_REPORT_AGE_MS = 30 * 24 * 60 * 60_000;
export const COMMUNITY_REPORT_RETENTION_MS = 90 * 24 * 60 * 60_000;
export const COMMUNITY_REVIEW_MIN_SPAN_MS = 6 * 60 * 60_000;
const MAX_FUTURE_SKEW_MS = 5 * 60_000;
const EXPLICIT_SCAM_BASE_WEIGHT = 5;
const BLOCK_FEEDBACK_BASE_WEIGHT = 2;
const UNATTESTED_REPORT_BASE_WEIGHT = 1;
const REPUTATION_MIN_RESOLVED_CASES = 3;
const DEFAULT_SNAPSHOT_INTERVAL = 500;
const REPORT_VERDICTS = new Set(["safe", "unknown", "review", "high_risk", "confirmed_threat"]);
const REPORT_INDICATOR_TYPES = new Set(["sender", "reply_to_domain", "url_domain", "attachment_hash", "campaign"]);
const REVIEWER_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{1,79}$/;
const MAX_REVIEW_REASON_CHARS = 500;
const ENVELOPE_WITHOUT_CIPHERTEXT_BYTES = Buffer.byteLength(JSON.stringify({
  version: 1,
  algorithm: ALGORITHM,
  iv: Buffer.alloc(12).toString("base64"),
  authTag: Buffer.alloc(16).toString("base64"),
  ciphertext: "",
}), "utf8");

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

interface CommunityJournalEvent {
  version: 1;
  acceptedAt: string;
  report: CommunityReportSubmission;
}

interface StorageFingerprint {
  exists: boolean;
  device: number;
  inode: number;
  size: number;
  modifiedMs: number;
  changedMs: number;
}

const MISSING_FINGERPRINT: StorageFingerprint = {
  exists: false,
  device: 0,
  inode: 0,
  size: 0,
  modifiedMs: 0,
  changedMs: 0,
};

function sameFingerprint(left: StorageFingerprint, right: StorageFingerprint): boolean {
  return left.exists === right.exists && left.device === right.device && left.inode === right.inode &&
    left.size === right.size && left.modifiedMs === right.modifiedMs && left.changedMs === right.changedMs;
}

export interface CommunityThresholds {
  warningReporters: number;
  warningWeight: number;
  confirmedReporters: number;
  confirmedStrongReporters: number;
  confirmedWeight: number;
}

export const DEFAULT_COMMUNITY_THRESHOLDS: CommunityThresholds = {
  warningReporters: 3,
  warningWeight: 15,
  confirmedReporters: 5,
  confirmedStrongReporters: 5,
  confirmedWeight: 25,
};

export interface CommunityAggregateStoreOptions {
  now?: () => Date;
  snapshotInterval?: number;
}

export interface CommunityReviewCandidate {
  campaignFingerprint: string;
  independentReporters: number;
  strongReporters: number;
  weightedScore: number;
  distinctUtcDays: number;
  observedSpanMs: number;
  firstSeen: string;
  lastSeen: string;
  createdAt: string;
}

export interface CommunityReviewResolution {
  campaignFingerprint: string;
  decision: "approved" | "rejected";
  resolvedAt: string;
  reporterHistoriesUpdated: number;
}

function emptyDatabase(): StoredCommunityDatabase {
  return { version: 3, campaigns: {}, reporterReputation: {} };
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(20, Number.isFinite(value) ? Math.round(value) : 0));
}

function isLegitimate(record: Pick<StoredCommunityReporterRecord, "evidenceCodes">): boolean {
  return hasLegitimateFeedback(record.evidenceCodes);
}

function isExplicitScam(record: Pick<StoredCommunityReporterRecord, "evidenceCodes">): boolean {
  return !isLegitimate(record) && hasExplicitScamFeedback(record.evidenceCodes);
}

function reputationMultiplier(record: StoredCommunityReporterReputation | undefined): number {
  if (!record || record.resolvedCases < REPUTATION_MIN_RESOLVED_CASES) return 1;
  const accuracy = record.alignedCases / record.resolvedCases;
  return Math.max(0.5, Math.min(1.5, 0.5 + accuracy));
}

function reporterWeight(
  record: Pick<StoredCommunityReporterRecord, "evidenceCodes">,
  reputation?: StoredCommunityReporterReputation,
): number {
  if (isLegitimate(record)) return 0;
  const base = isExplicitScam(record)
    ? EXPLICIT_SCAM_BASE_WEIGHT
    : hasBlockFeedback(record.evidenceCodes)
      ? BLOCK_FEEDBACK_BASE_WEIGHT
      : UNATTESTED_REPORT_BASE_WEIGHT;
  return base * reputationMultiplier(reputation);
}

function isStrong(record: StoredCommunityReporterRecord): boolean {
  return isExplicitScam(record);
}

interface CampaignMetrics {
  reporters: number;
  weight: number;
  strong: number;
}

interface TemporalSpread {
  spanMs: number;
  distinctUtcDays: number;
}

const ZERO_METRICS: CampaignMetrics = { reporters: 0, weight: 0, strong: 0 };

function reporterContribution(
  record: StoredCommunityReporterRecord | undefined,
  reputation?: StoredCommunityReporterReputation,
): CampaignMetrics {
  if (!record || isLegitimate(record)) return ZERO_METRICS;
  return {
    reporters: 1,
    weight: reporterWeight(record, reputation),
    strong: isStrong(record) ? 1 : 0,
  };
}

function metricsFor(
  record: StoredCommunityCampaignRecord,
  reputation: StoredCommunityDatabase["reporterReputation"],
): CampaignMetrics {
  return Object.entries(record.reporters).reduce<CampaignMetrics>((metrics, [proof, reporter]) => {
    const contribution = reporterContribution(reporter, reputation[proof]);
    metrics.reporters += contribution.reporters;
    metrics.weight += contribution.weight;
    metrics.strong += contribution.strong;
    return metrics;
  }, { ...ZERO_METRICS });
}

function temporalSpread(record: StoredCommunityCampaignRecord): TemporalSpread {
  const times = Object.values(record.reporters)
    .filter(isStrong)
    .map((reporter) => Date.parse(reporter.reportedAt))
    .filter(Number.isFinite);
  if (times.length === 0) return { spanMs: 0, distinctUtcDays: 0 };
  const days = new Set(times.map((timestamp) => new Date(timestamp).toISOString().slice(0, 10)));
  return {
    spanMs: Math.max(...times) - Math.min(...times),
    distinctUtcDays: days.size,
  };
}

function temporalSpreadAfterReport(
  record: StoredCommunityCampaignRecord | undefined,
  reporterProof: string,
  candidate: StoredCommunityReporterRecord,
): TemporalSpread {
  const times: number[] = [];
  let replaced = false;
  for (const [proof, reporter] of Object.entries(record?.reporters ?? {})) {
    const effective = proof === reporterProof ? candidate : reporter;
    if (proof === reporterProof) replaced = true;
    if (isStrong(effective)) times.push(Date.parse(effective.reportedAt));
  }
  if (!replaced && isStrong(candidate)) times.push(Date.parse(candidate.reportedAt));
  const valid = times.filter(Number.isFinite);
  if (valid.length === 0) return { spanMs: 0, distinctUtcDays: 0 };
  const days = new Set(valid.map((timestamp) => new Date(timestamp).toISOString().slice(0, 10)));
  return {
    spanMs: Math.max(...valid) - Math.min(...valid),
    distinctUtcDays: days.size,
  };
}

function meetsWarningThreshold(metrics: CampaignMetrics, thresholds: CommunityThresholds): boolean {
  return metrics.reporters >= thresholds.warningReporters && metrics.weight >= thresholds.warningWeight;
}

function meetsReviewThreshold(metrics: CampaignMetrics, spread: TemporalSpread, thresholds: CommunityThresholds): boolean {
  return metrics.reporters >= thresholds.confirmedReporters &&
    metrics.strong >= thresholds.confirmedStrongReporters &&
    metrics.weight >= thresholds.confirmedWeight &&
    spread.spanMs >= COMMUNITY_REVIEW_MIN_SPAN_MS &&
    spread.distinctUtcDays >= 2;
}

function statusFor(
  record: StoredCommunityCampaignRecord,
  database: StoredCommunityDatabase,
  thresholds: CommunityThresholds,
): CommunityCampaignStatus {
  const metrics = metricsFor(record, database.reporterReputation);
  const spread = temporalSpread(record);
  if (record.review?.status === "approved" && meetsReviewThreshold(metrics, spread, thresholds)) return "confirmed";
  if (meetsWarningThreshold(metrics, thresholds)) return "warning";
  return "candidate";
}

function legitimateReporterCount(record: StoredCommunityCampaignRecord | undefined): number {
  return record ? Object.values(record.reporters).filter(isLegitimate).length : 0;
}

function indicatorKey(indicator: CommunityIndicator): string {
  return `${indicator.type}\0${indicator.value.toLowerCase()}`;
}

function ruleId(campaign: string, indicator: CommunityIndicator): string {
  return `community:${createHash("sha256").update(`${campaign}\0${indicator.type}\0${indicator.value}`).digest("hex").slice(0, 24)}`;
}

function legitimateRuleId(campaign: string): string {
  return `${LEGITIMATE_RULE_PREFIX}${createHash("sha256").update(`legitimate\0${campaign}`).digest("hex").slice(0, 24)}`;
}

function observedWindow(reporters: StoredCommunityReporterRecord[], fallback: StoredCommunityCampaignRecord): { firstSeen: string; lastSeen: string } {
  if (!reporters.length) return { firstSeen: fallback.firstSeen, lastSeen: fallback.lastSeen };
  const times = reporters.map((reporter) => Date.parse(reporter.reportedAt)).filter(Number.isFinite);
  if (!times.length) return { firstSeen: fallback.firstSeen, lastSeen: fallback.lastSeen };
  return {
    firstSeen: new Date(Math.min(...times)).toISOString(),
    lastSeen: new Date(Math.max(...times)).toISOString(),
  };
}

function encryptedEnvelopeByteLength(plaintextBytes: number): number {
  return ENVELOPE_WITHOUT_CIPHERTEXT_BYTES + (4 * Math.ceil(plaintextBytes / 3));
}

function validateSubmission(
  input: CommunityReportSubmission,
  nowMs: number,
  enforceSubmissionWindow = true,
): CommunityReportSubmission {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new CommunityReportValidationError("Community report body is invalid.");
  }
  if (input.schemaVersion !== 1) throw new CommunityReportValidationError("Unsupported community report schema.");
  if (typeof input.reporterProof !== "string" || !/^[a-f0-9]{64}$/.test(input.reporterProof)) {
    throw new CommunityReportValidationError("Reporter proof is invalid.");
  }
  if (typeof input.campaignFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(input.campaignFingerprint)) {
    throw new CommunityReportValidationError("Campaign fingerprint is invalid.");
  }
  if (typeof input.reportedAt !== "string" || input.reportedAt.length > 64) {
    throw new CommunityReportValidationError("Report timestamp is invalid.");
  }
  const reportedAt = Date.parse(input.reportedAt);
  if (!Number.isFinite(reportedAt)) throw new CommunityReportValidationError("Report timestamp is invalid.");
  if (enforceSubmissionWindow && (reportedAt > nowMs + MAX_FUTURE_SKEW_MS || reportedAt < nowMs - MAX_REPORT_AGE_MS)) {
    throw new CommunityReportValidationError("Report timestamp is outside the accepted submission window.");
  }
  if (typeof input.verdict !== "string" || !REPORT_VERDICTS.has(input.verdict)) {
    throw new CommunityReportValidationError("Community report verdict is invalid.");
  }
  if (typeof input.evidenceScore !== "number" || !Number.isFinite(input.evidenceScore)) {
    throw new CommunityReportValidationError("Community report evidence score is invalid.");
  }
  if (!Array.isArray(input.evidenceCodes) || input.evidenceCodes.length > 64) {
    throw new CommunityReportValidationError("Community report evidence codes are invalid.");
  }
  if (!input.evidenceCodes.every((code): code is string => typeof code === "string" && /^[A-Z0-9_]{2,80}$/.test(code))) {
    throw new CommunityReportValidationError("Community report evidence codes are invalid.");
  }
  if (hasLegitimateFeedback(input.evidenceCodes) && (
    input.evidenceCodes.length !== 1 || input.verdict !== "safe" || clampScore(input.evidenceScore) !== 0
  )) {
    throw new CommunityReportValidationError("Legitimate feedback must be an isolated zero-risk Safe judgment.");
  }
  if (!Array.isArray(input.indicators) || input.indicators.length === 0 || input.indicators.length > MAX_INDICATORS_PER_REPORT) {
    throw new CommunityReportValidationError("Community report indicators are invalid.");
  }

  const indicators: CommunityIndicator[] = [];
  const seen = new Set<string>();
  for (const indicator of input.indicators) {
    if (!indicator || typeof indicator !== "object" || Array.isArray(indicator)) {
      throw new CommunityReportValidationError("Community report indicator is invalid.");
    }
    if (typeof indicator.type !== "string" || !REPORT_INDICATOR_TYPES.has(indicator.type) || typeof indicator.value !== "string") {
      throw new CommunityReportValidationError("Community report indicator is invalid.");
    }
    const value = indicator.value.trim().toLowerCase();
    if (!value || value.length > 512) throw new CommunityReportValidationError("Community report indicator is invalid.");
    if (indicator.type === "campaign" && value !== input.campaignFingerprint) {
      throw new CommunityReportValidationError("Community report campaign indicator is inconsistent.");
    }
    const key = `${indicator.type}\0${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    indicators.push({ type: indicator.type as CommunityIndicator["type"], value });
  }
  if (!indicators.some((item) => item.type === "campaign" && item.value === input.campaignFingerprint)) {
    indicators.unshift({ type: "campaign", value: input.campaignFingerprint });
  }

  return {
    schemaVersion: 1,
    reporterProof: input.reporterProof,
    campaignFingerprint: input.campaignFingerprint,
    reportedAt: new Date(reportedAt).toISOString(),
    verdict: input.verdict,
    evidenceScore: clampScore(input.evidenceScore),
    evidenceCodes: [...new Set(input.evidenceCodes)].sort(),
    indicators,
  };
}

function reporterFromReport(report: CommunityReportSubmission, acceptedAt: string): StoredCommunityReporterRecord {
  return {
    reportedAt: acceptedAt,
    evidenceScore: report.evidenceScore,
    verdict: report.verdict,
    evidenceCodes: [...report.evidenceCodes],
    indicators: [...report.indicators].sort((left, right) => indicatorKey(left).localeCompare(indicatorKey(right))),
  };
}

function mergedReporter(
  prior: StoredCommunityReporterRecord | undefined,
  report: CommunityReportSubmission,
  acceptedAt: string,
): StoredCommunityReporterRecord {
  const incoming = reporterFromReport(report, acceptedAt);
  if (!prior || isLegitimate(prior) !== isLegitimate(incoming)) {
    // Changing from legitimate to threat feedback (or the reverse) replaces
    // the reporter's polarity. Contradictory judgments are never accumulated.
    return incoming;
  }
  if (isLegitimate(incoming)) return incoming;

  return {
    reportedAt: acceptedAt,
    // Client detector severity is retained only as diagnostic evidence. It is
    // deliberately excluded from central trust/confidence calculations.
    evidenceScore: Math.max(prior.evidenceScore, report.evidenceScore),
    verdict: prior.verdict === "confirmed_threat" ? prior.verdict : report.verdict,
    evidenceCodes: [...new Set([...prior.evidenceCodes, ...report.evidenceCodes])].sort(),
    indicators: [...new Map(
      [...prior.indicators, ...report.indicators].map((indicator) => [indicatorKey(indicator), indicator]),
    ).values()].sort((left, right) => indicatorKey(left).localeCompare(indicatorKey(right))),
  };
}

function applyReportToDatabase(
  database: StoredCommunityDatabase,
  report: CommunityReportSubmission,
  acceptedAt: string,
): void {
  const campaign = database.campaigns[report.campaignFingerprint];
  const reporter = mergedReporter(campaign?.reporters[report.reporterProof], report, acceptedAt);
  if (campaign) {
    campaign.reporters[report.reporterProof] = reporter;
    if (acceptedAt < campaign.firstSeen) campaign.firstSeen = acceptedAt;
    if (acceptedAt > campaign.lastSeen) campaign.lastSeen = acceptedAt;
  } else {
    database.campaigns[report.campaignFingerprint] = {
      firstSeen: acceptedAt,
      lastSeen: acceptedAt,
      reporters: { [report.reporterProof]: reporter },
      review: null,
    };
  }
}

function reporterEntryBytes(proof: string, reporter: StoredCommunityReporterRecord): number {
  return Buffer.byteLength(`${JSON.stringify(proof)}:${JSON.stringify(reporter)}`, "utf8");
}

function campaignEntryBytes(fingerprint: string, campaign: StoredCommunityCampaignRecord): number {
  return Buffer.byteLength(`${JSON.stringify(fingerprint)}:${JSON.stringify(campaign)}`, "utf8");
}

function reviewCandidate(createdAt: string): StoredCommunityReviewRecord {
  return { status: "candidate", createdAt, resolvedAt: null, reviewerId: null, reason: null };
}

function reviewReplacement(
  prior: StoredCommunityReviewRecord | null,
  metrics: CampaignMetrics,
  spread: TemporalSpread,
  thresholds: CommunityThresholds,
  acceptedAt: string,
  allowReopen: boolean,
): StoredCommunityReviewRecord | null {
  if (!meetsReviewThreshold(metrics, spread, thresholds)) return prior;
  if (prior === null) return reviewCandidate(acceptedAt);
  if (prior.status === "rejected" && allowReopen) return reviewCandidate(acceptedAt);
  return prior;
}

function pruneExpired(database: StoredCommunityDatabase, nowMs: number): boolean {
  const cutoff = nowMs - COMMUNITY_REPORT_RETENTION_MS;
  let changed = false;
  for (const [fingerprint, campaign] of Object.entries(database.campaigns)) {
    const reporters = Object.fromEntries(Object.entries(campaign.reporters).filter(([, reporter]) => Date.parse(reporter.reportedAt) >= cutoff));
    if (Object.keys(reporters).length === Object.keys(campaign.reporters).length) continue;
    changed = true;
    if (Object.keys(reporters).length === 0) {
      delete database.campaigns[fingerprint];
      continue;
    }
    const timestamps = Object.values(reporters).map((item) => Date.parse(item.reportedAt));
    database.campaigns[fingerprint] = {
      firstSeen: new Date(Math.min(...timestamps)).toISOString(),
      lastSeen: new Date(Math.max(...timestamps)).toISOString(),
      reporters,
      review: campaign.review,
    };
  }
  return changed;
}

export class EncryptedCommunityAggregateStore {
  private readonly keyPath: string;
  private readonly databasePath: string;
  private readonly journalPath: string;
  private readonly now: () => Date;
  private readonly snapshotInterval: number;
  private keyCache: Buffer | null = null;
  private databaseCache: StoredCommunityDatabase | null = null;
  private reporterActivity = new Map<string, Map<string, number>>();
  private campaignMetrics = new Map<string, CampaignMetrics>();
  private snapshotPlaintextBytes = 0;
  private nextPruneAt = 0;
  private journalEvents = 0;
  private journalBytes = 0;
  private snapshotFingerprint: StorageFingerprint = MISSING_FINGERPRINT;
  private journalFingerprint: StorageFingerprint = MISSING_FINGERPRINT;
  private journalDescriptor: number | null = null;

  constructor(
    private readonly dataDirectory: string,
    private readonly thresholds: CommunityThresholds = DEFAULT_COMMUNITY_THRESHOLDS,
    options: CommunityAggregateStoreOptions = {},
  ) {
    this.keyPath = join(dataDirectory, "community-storage.key");
    this.databasePath = join(dataDirectory, COMMUNITY_REPORT_DATABASE_FILE);
    this.journalPath = join(dataDirectory, COMMUNITY_REPORT_JOURNAL_FILE);
    this.now = options.now ?? (() => new Date());
    this.snapshotInterval = Math.max(1, Math.floor(options.snapshotInterval ?? DEFAULT_SNAPSHOT_INTERVAL));
  }

  accept(input: CommunityReportSubmission): CommunityReportReceipt {
    const now = this.now();
    const nowMs = now.getTime();
    const report = validateSubmission(input, nowMs);
    const database = this.loadDatabase(nowMs, false);
    const needsInitialSnapshot = !existsSync(this.databasePath);
    const existing = database.campaigns[report.campaignFingerprint];
    const activity = this.reporterActivity.get(report.reporterProof);
    const reportsToday = [...(activity?.values() ?? [])].filter((acceptedAt) => acceptedAt >= nowMs - 24 * 60 * 60_000).length;
    const duplicate = Boolean(existing?.reporters[report.reporterProof]);
    if (!duplicate && reportsToday >= MAX_REPORTS_PER_REPORTER_PER_DAY) throw new CommunityReportRateLimitError();
    if (!existing && Object.keys(database.campaigns).length >= MAX_CAMPAIGNS) throw new CommunityReportCapacityError();

    const acceptedAt = now.toISOString();
    const previousMetrics = this.campaignMetrics.get(report.campaignFingerprint) ?? { ...ZERO_METRICS };
    const previousStatus = existing ? statusFor(existing, database, this.thresholds) : "candidate";
    const previousLegitimate = legitimateReporterCount(existing);
    const previousPositiveConsensus = previousLegitimate >= LEGITIMATE_CONSENSUS_REPORTERS && previousMetrics.reporters === 0;
    const priorReporter = existing?.reporters[report.reporterProof];
    const candidateReporter = mergedReporter(priorReporter, report, acceptedAt);
    const reputation = database.reporterReputation[report.reporterProof];
    const priorContribution = reporterContribution(priorReporter, reputation);
    const nextContribution = reporterContribution(candidateReporter, reputation);
    const nextMetrics: CampaignMetrics = {
      reporters: previousMetrics.reporters - priorContribution.reporters + nextContribution.reporters,
      weight: previousMetrics.weight - priorContribution.weight + nextContribution.weight,
      strong: previousMetrics.strong - priorContribution.strong + nextContribution.strong,
    };
    const nextSpread = temporalSpreadAfterReport(existing, report.reporterProof, candidateReporter);
    const nextReview = reviewReplacement(existing?.review ?? null, nextMetrics, nextSpread, this.thresholds, acceptedAt, !duplicate);

    let candidatePlaintextBytes: number;
    if (existing) {
      const previousEntryBytes = priorReporter ? reporterEntryBytes(report.reporterProof, priorReporter) : 0;
      const nextEntryBytes = reporterEntryBytes(report.reporterProof, candidateReporter);
      const reviewDelta = Buffer.byteLength(JSON.stringify(nextReview), "utf8") - Buffer.byteLength(JSON.stringify(existing.review), "utf8");
      candidatePlaintextBytes = this.snapshotPlaintextBytes + nextEntryBytes - previousEntryBytes + (priorReporter ? 0 : 1) + reviewDelta;
    } else {
      const candidateCampaign: StoredCommunityCampaignRecord = {
        firstSeen: acceptedAt,
        lastSeen: acceptedAt,
        reporters: { [report.reporterProof]: candidateReporter },
        review: nextReview,
      };
      candidatePlaintextBytes = this.snapshotPlaintextBytes + campaignEntryBytes(report.campaignFingerprint, candidateCampaign) +
        (Object.keys(database.campaigns).length > 0 ? 1 : 0);
    }
    this.assertSnapshotCapacityBytes(candidatePlaintextBytes);

    const event: CommunityJournalEvent = { version: 1, acceptedAt, report };
    const line = `${JSON.stringify(this.encryptJson(event, JOURNAL_AAD))}\n`;
    const lineBytes = Buffer.byteLength(line, "utf8");
    if (this.journalBytes + lineBytes > MAX_COMMUNITY_REPORT_JOURNAL_BYTES) this.compact(database);
    if (this.journalBytes + lineBytes > MAX_COMMUNITY_REPORT_JOURNAL_BYTES) throw new CommunityReportCapacityError();
    this.appendJournal(line);

    applyReportToDatabase(database, report, acceptedAt);
    database.campaigns[report.campaignFingerprint]!.review = nextReview;
    this.databaseCache = database;
    this.snapshotPlaintextBytes = candidatePlaintextBytes;
    this.campaignMetrics.set(report.campaignFingerprint, nextMetrics);
    const nextLegitimate = previousLegitimate - (priorReporter && isLegitimate(priorReporter) ? 1 : 0) + (isLegitimate(candidateReporter) ? 1 : 0);
    const nextPositiveConsensus = nextLegitimate >= LEGITIMATE_CONSENSUS_REPORTERS && nextMetrics.reporters === 0;
    const reporterCampaigns = this.reporterActivity.get(report.reporterProof) ?? new Map<string, number>();
    reporterCampaigns.set(report.campaignFingerprint, nowMs);
    this.reporterActivity.set(report.reporterProof, reporterCampaigns);
    this.nextPruneAt = this.nextPruneAt === 0
      ? nowMs + COMMUNITY_REPORT_RETENTION_MS
      : Math.min(this.nextPruneAt, nowMs + COMMUNITY_REPORT_RETENTION_MS);
    this.journalEvents++;
    if (needsInitialSnapshot) {
      this.compact(database);
    } else if (this.journalEvents >= this.snapshotInterval) {
      try { this.compact(database); } catch { /* the accepted report remains durable in the journal */ }
    }

    const status = statusFor(database.campaigns[report.campaignFingerprint]!, database, this.thresholds);
    return {
      accepted: true,
      duplicate,
      queued: false,
      campaignFingerprint: report.campaignFingerprint,
      independentReporters: isLegitimate(candidateReporter) ? nextLegitimate : nextMetrics.reporters,
      status,
      feedUpdated: status !== previousStatus || previousPositiveConsensus !== nextPositiveConsensus,
    };
  }

  listReviewCandidates(): CommunityReviewCandidate[] {
    const database = this.loadDatabase(this.now().getTime());
    const candidates: CommunityReviewCandidate[] = [];
    for (const [campaignFingerprint, campaign] of Object.entries(database.campaigns)) {
      if (campaign.review?.status !== "candidate") continue;
      const metrics = metricsFor(campaign, database.reporterReputation);
      const spread = temporalSpread(campaign);
      if (!meetsReviewThreshold(metrics, spread, this.thresholds)) continue;
      candidates.push({
        campaignFingerprint,
        independentReporters: metrics.reporters,
        strongReporters: metrics.strong,
        weightedScore: Math.round(metrics.weight * 100) / 100,
        distinctUtcDays: spread.distinctUtcDays,
        observedSpanMs: spread.spanMs,
        firstSeen: campaign.firstSeen,
        lastSeen: campaign.lastSeen,
        createdAt: campaign.review.createdAt,
      });
    }
    return candidates.sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  resolveReviewCandidate(input: {
    campaignFingerprint: string;
    decision: "approved" | "rejected";
    reviewerId: string;
    reason: string;
  }): CommunityReviewResolution {
    if (!/^[a-f0-9]{64}$/.test(input.campaignFingerprint)) throw new CommunityReportValidationError("Review campaign fingerprint is invalid.");
    if (input.decision !== "approved" && input.decision !== "rejected") throw new CommunityReportValidationError("Review decision is invalid.");
    if (!REVIEWER_ID_RE.test(input.reviewerId)) throw new CommunityReportValidationError("Review operator ID is invalid.");
    const reason = input.reason.trim();
    if (!reason || reason.length > MAX_REVIEW_REASON_CHARS || /[\u0000-\u001f\u007f]/.test(reason)) {
      throw new CommunityReportValidationError("Review reason is invalid.");
    }

    const now = this.now();
    const database = this.loadDatabase(now.getTime(), false);
    const campaign = database.campaigns[input.campaignFingerprint];
    if (!campaign || campaign.review?.status !== "candidate") throw new CommunityReportValidationError("Campaign is not awaiting human review.");
    const metrics = metricsFor(campaign, database.reporterReputation);
    const spread = temporalSpread(campaign);
    if (!meetsReviewThreshold(metrics, spread, this.thresholds)) throw new CommunityReportValidationError("Campaign no longer meets the corroboration boundary for human review.");

    const previousReview = structuredClone(campaign.review);
    const previousReputation = new Map<string, StoredCommunityReporterReputation | undefined>();
    const resolvedAt = now.toISOString();
    campaign.review = {
      status: input.decision,
      createdAt: previousReview.createdAt,
      resolvedAt,
      reviewerId: input.reviewerId,
      reason,
    };
    for (const [proof, reporter] of Object.entries(campaign.reporters)) {
      previousReputation.set(proof, database.reporterReputation[proof] ? { ...database.reporterReputation[proof]! } : undefined);
      const prior = database.reporterReputation[proof] ?? { resolvedCases: 0, alignedCases: 0 };
      const threatReporter = !isLegitimate(reporter);
      const aligned = input.decision === "approved" ? threatReporter : !threatReporter;
      database.reporterReputation[proof] = {
        resolvedCases: prior.resolvedCases + 1,
        alignedCases: prior.alignedCases + (aligned ? 1 : 0),
      };
    }

    try {
      this.assertSnapshotCapacity(database);
      this.compact(database);
      this.rebuildIndexes(database);
    } catch (error) {
      campaign.review = previousReview;
      for (const [proof, prior] of previousReputation) {
        if (prior) database.reporterReputation[proof] = prior;
        else delete database.reporterReputation[proof];
      }
      this.rebuildIndexes(database);
      throw error;
    }

    return {
      campaignFingerprint: input.campaignFingerprint,
      decision: input.decision,
      resolvedAt,
      reporterHistoriesUpdated: previousReputation.size,
    };
  }

  close(): void {
    if (this.journalDescriptor === null) return;
    closeSync(this.journalDescriptor);
    this.journalDescriptor = null;
  }

  buildFeedPayload(now = this.now()): CommunityFeedPayload {
    const database = this.loadDatabase(now.getTime());
    const entries: SignedFeedEntry[] = [];
    for (const [fingerprint, campaign] of Object.entries(database.campaigns)) {
      const metrics = metricsFor(campaign, database.reporterReputation);
      const status = statusFor(campaign, database, this.thresholds);
      const reporters = Object.entries(campaign.reporters);
      const threatReporters = reporters.filter(([, reporter]) => !isLegitimate(reporter));
      const legitimateReporters = reporters.filter(([, reporter]) => isLegitimate(reporter));

      if (status === "candidate") {
        // Positive learning is campaign-specific, requires a much larger
        // independent consensus, and disappears as soon as any unresolved
        // threat reporter exists. It is never emitted for sender/domain/url.
        if (metrics.reporters === 0 && legitimateReporters.length >= LEGITIMATE_CONSENSUS_REPORTERS) {
          const window = observedWindow(legitimateReporters.map(([, reporter]) => reporter), campaign);
          entries.push({
            type: "campaign",
            value: fingerprint,
            confirmedThreat: false,
            ruleId: legitimateRuleId(fingerprint),
            independentReports: legitimateReporters.length,
            firstSeen: window.firstSeen,
            lastSeen: window.lastSeen,
          });
        }
        continue;
      }

      const minimumSupport = status === "confirmed" ? this.thresholds.confirmedReporters : this.thresholds.warningReporters;
      const support = new Map<string, { indicator: CommunityIndicator; reporters: Set<string> }>();
      for (const [proof, reporter] of threatReporters) {
        for (const indicator of reporter.indicators) {
          const key = indicatorKey(indicator);
          const item = support.get(key) ?? { indicator, reporters: new Set<string>() };
          item.reporters.add(proof);
          support.set(key, item);
        }
      }
      const window = observedWindow(threatReporters.map(([, reporter]) => reporter), campaign);
      for (const { indicator, reporters: supportingReporters } of support.values()) {
        if (supportingReporters.size < minimumSupport) continue;
        entries.push({
          type: indicator.type,
          value: indicator.value,
          confirmedThreat: status === "confirmed",
          ruleId: ruleId(fingerprint, indicator),
          independentReports: metrics.reporters,
          firstSeen: window.firstSeen,
          lastSeen: window.lastSeen,
        });
      }
    }
    entries.sort((a, b) => `${a.type}:${a.value}:${a.ruleId}`.localeCompare(`${b.type}:${b.value}:${b.ruleId}`));
    return {
      version: 1,
      generatedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 24 * 60 * 60_000).toISOString(),
      entries,
    };
  }

  stats(): { campaigns: number; warnings: number; confirmed: number } {
    const database = this.loadDatabase(this.now().getTime());
    let warnings = 0;
    let confirmed = 0;
    for (const campaign of Object.values(database.campaigns)) {
      const status = statusFor(campaign, database, this.thresholds);
      if (status === "warning") warnings++;
      if (status === "confirmed") confirmed++;
    }
    return { campaigns: Object.keys(database.campaigns).length, warnings, confirmed };
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readKey(): Buffer {
    if (this.keyCache) return this.keyCache;
    this.ensureDirectory();
    if (!existsSync(this.keyPath)) {
      const generated = randomBytes(COMMUNITY_STORAGE_KEY_BYTES);
      try { writeFileSync(this.keyPath, generated, { mode: 0o600, flag: "wx" }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      finally { generated.fill(0); }
    }
    let key: Buffer;
    try {
      key = readBoundedRegularFile(this.keyPath, {
        description: "Community storage encryption key",
        maxBytes: COMMUNITY_STORAGE_KEY_BYTES,
        exactBytes: COMMUNITY_STORAGE_KEY_BYTES,
        requireOwnerOnly: true,
      });
    } catch (error) {
      throw new Error(`Community storage encryption key is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    try { chmodSync(this.keyPath, 0o600); } catch {}
    this.keyCache = key;
    return key;
  }

  private encryptJson(value: unknown, aad: Buffer): EncryptedEnvelope {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.readKey(), iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return {
      version: 1,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
  }

  private decryptJson(envelope: EncryptedEnvelope, aad: Buffer): unknown {
    if (envelope.version !== 1 || envelope.algorithm !== ALGORITHM) throw new Error("Unsupported encrypted community format.");
    const decipher = createDecipheriv(ALGORITHM, this.readKey(), Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
    return JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8"));
  }

  private loadDatabase(nowMs: number, verifyStorage = true): StoredCommunityDatabase {
    if (this.databaseCache) {
      if (verifyStorage) this.assertAuthoritativeStorageUnchanged();
      if (nowMs >= this.nextPruneAt) {
        if (pruneExpired(this.databaseCache, nowMs)) {
          this.rebuildIndexes(this.databaseCache);
          this.compact(this.databaseCache);
        } else {
          this.recomputeNextPruneAt(this.databaseCache);
        }
      }
      return this.databaseCache;
    }
    let database = emptyDatabase();
    if (existsSync(this.databasePath)) {
      try {
        const serialized = readBoundedUtf8File(this.databasePath, {
          description: "Encrypted community report database",
          maxBytes: MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES,
        });
        database = validateStoredCommunityDatabase(
          this.decryptJson(JSON.parse(serialized) as EncryptedEnvelope, SNAPSHOT_AAD),
          MAX_CAMPAIGNS,
        );
      } catch (error) {
        throw new Error(`Encrypted community report database could not be read within the recoverable storage boundary: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    if (existsSync(this.journalPath)) {
      let serialized: string;
      try {
        serialized = readBoundedUtf8File(this.journalPath, {
          description: "Encrypted community report journal",
          maxBytes: MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
          requireOwnerOnly: true,
        });
      } catch (error) {
        throw new Error(`Encrypted community report journal could not be read: ${error instanceof Error ? error.message : String(error)}`);
      }
      this.journalBytes = Buffer.byteLength(serialized, "utf8");
      const complete = serialized.endsWith("\n") ? serialized : serialized.slice(0, serialized.lastIndexOf("\n") + 1);
      const completeBytes = Buffer.byteLength(complete, "utf8");
      if (completeBytes !== this.journalBytes) {
        this.truncateJournalTo(completeBytes, this.journalBytes);
        this.journalBytes = completeBytes;
      }
      for (const line of complete.split("\n")) {
        if (!line) continue;
        try {
          const raw = this.decryptJson(JSON.parse(line) as EncryptedEnvelope, JOURNAL_AAD) as Partial<CommunityJournalEvent>;
          if (raw.version !== 1 || typeof raw.acceptedAt !== "string" || !raw.report) throw new Error("Invalid journal event.");
          const acceptedAtMs = Date.parse(raw.acceptedAt);
          if (!Number.isFinite(acceptedAtMs) || new Date(acceptedAtMs).toISOString() !== raw.acceptedAt) throw new Error("Invalid journal timestamp.");
          const report = validateSubmission(raw.report, acceptedAtMs, false);
          const priorReporter = database.campaigns[report.campaignFingerprint]?.reporters[report.reporterProof];
          applyReportToDatabase(database, report, raw.acceptedAt);
          const campaign = database.campaigns[report.campaignFingerprint]!;
          campaign.review = reviewReplacement(
            campaign.review,
            metricsFor(campaign, database.reporterReputation),
            temporalSpread(campaign),
            this.thresholds,
            raw.acceptedAt,
            !priorReporter,
          );
          this.journalEvents++;
        } catch (error) {
          throw new Error(`Encrypted community report journal is invalid: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    pruneExpired(database, nowMs);
    validateStoredCommunityDatabase(database, MAX_CAMPAIGNS);
    this.databaseCache = database;
    this.rebuildIndexes(database);
    this.captureAuthoritativeStorageFingerprints();
    return database;
  }

  private rebuildIndexes(database: StoredCommunityDatabase): void {
    this.rebuildReporterActivity(database);
    this.snapshotPlaintextBytes = Buffer.byteLength(JSON.stringify(database), "utf8");
    this.campaignMetrics = new Map(Object.entries(database.campaigns).map(([fingerprint, campaign]) => [
      fingerprint,
      metricsFor(campaign, database.reporterReputation),
    ]));
    this.recomputeNextPruneAt(database);
  }

  private recomputeNextPruneAt(database: StoredCommunityDatabase): void {
    let earliest = Number.POSITIVE_INFINITY;
    for (const campaign of Object.values(database.campaigns)) {
      for (const reporter of Object.values(campaign.reporters)) earliest = Math.min(earliest, Date.parse(reporter.reportedAt));
    }
    this.nextPruneAt = Number.isFinite(earliest) ? earliest + COMMUNITY_REPORT_RETENTION_MS : Number.POSITIVE_INFINITY;
  }

  private rebuildReporterActivity(database: StoredCommunityDatabase): void {
    this.reporterActivity.clear();
    for (const [campaign, record] of Object.entries(database.campaigns)) {
      for (const [proof, reporter] of Object.entries(record.reporters)) {
        const campaigns = this.reporterActivity.get(proof) ?? new Map<string, number>();
        campaigns.set(campaign, Date.parse(reporter.reportedAt));
        this.reporterActivity.set(proof, campaigns);
      }
    }
  }

  private assertSnapshotCapacity(database: StoredCommunityDatabase): void {
    const plaintextBytes = Buffer.byteLength(JSON.stringify(database), "utf8");
    this.assertSnapshotCapacityBytes(plaintextBytes);
  }

  private assertSnapshotCapacityBytes(plaintextBytes: number): void {
    if (encryptedEnvelopeByteLength(plaintextBytes) > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) throw new CommunityReportCapacityError();
  }

  private appendJournal(line: string): void {
    this.ensureDirectory();
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    const descriptor = this.journalDescriptor ?? openSync(
      this.journalPath, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | noFollow, 0o600,
    );
    this.journalDescriptor = descriptor;
    const bytes = Buffer.from(line, "utf8");
    try {
      const initial = fstatSync(descriptor);
      const pathState = lstatSync(this.journalPath);
      if (!initial.isFile() || pathState.isSymbolicLink() || !pathState.isFile() ||
          initial.dev !== pathState.dev || initial.ino !== pathState.ino || initial.size !== this.journalBytes ||
          pathState.size !== this.journalBytes || initial.size + bytes.length > MAX_COMMUNITY_REPORT_JOURNAL_BYTES) {
        throw new CommunityReportCapacityError();
      }
      let offset = 0;
      while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset);
      const written = fstatSync(descriptor);
      if (written.size !== initial.size + bytes.length) throw new Error("Community report journal changed while being written.");
      try { chmodSync(this.journalPath, 0o600); } catch {}
      const committed = lstatSync(this.journalPath);
      this.journalFingerprint = {
        exists: true, device: committed.dev, inode: committed.ino, size: committed.size,
        modifiedMs: committed.mtimeMs, changedMs: committed.ctimeMs,
      };
    } catch (error) {
      this.close();
      throw error;
    } finally {
      bytes.fill(0);
    }
    this.journalBytes += Buffer.byteLength(line, "utf8");
  }

  private compact(database: StoredCommunityDatabase): void {
    this.assertAuthoritativeStorageUnchanged();
    this.close();
    this.writeDatabase(database);
    if (existsSync(this.journalPath)) {
      const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
      const descriptor = openSync(this.journalPath, fsConstants.O_WRONLY | noFollow);
      try {
        if (!fstatSync(descriptor).isFile()) throw new Error("Community report journal is not a regular file.");
        ftruncateSync(descriptor, 0);
      } finally {
        closeSync(descriptor);
      }
    }
    this.journalEvents = 0;
    this.journalBytes = 0;
    this.captureAuthoritativeStorageFingerprints();
  }

  private truncateJournalTo(size: number, expectedCurrentSize: number): void {
    this.close();
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    const descriptor = openSync(this.journalPath, fsConstants.O_WRONLY | noFollow);
    try {
      const current = fstatSync(descriptor);
      if (!current.isFile() || current.size !== expectedCurrentSize || size < 0 || size > current.size) {
        throw new Error("Community report journal changed while recovering its final record.");
      }
      ftruncateSync(descriptor, size);
    } finally {
      closeSync(descriptor);
    }
  }

  private writeDatabase(database: StoredCommunityDatabase): void {
    this.ensureDirectory();
    this.assertSnapshotCapacity(database);
    const serialized = JSON.stringify(this.encryptJson(database, SNAPSHOT_AAD));
    if (Buffer.byteLength(serialized, "utf8") > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) throw new CommunityReportCapacityError();
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(5).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }

  private fileFingerprint(path: string, description: string): StorageFingerprint {
    if (!existsSync(path)) return MISSING_FINGERPRINT;
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    let descriptor: number;
    try {
      descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
    } catch {
      throw new Error(`${description} could not be opened safely.`);
    }
    try {
      const state = fstatSync(descriptor);
      if (!state.isFile()) throw new Error(`${description} must be a regular file.`);
      return {
        exists: true,
        device: state.dev,
        inode: state.ino,
        size: state.size,
        modifiedMs: state.mtimeMs,
        changedMs: state.ctimeMs,
      };
    } finally {
      closeSync(descriptor);
    }
  }

  private captureAuthoritativeStorageFingerprints(): void {
    this.snapshotFingerprint = this.fileFingerprint(this.databasePath, "Encrypted community report database");
    this.journalFingerprint = this.fileFingerprint(this.journalPath, "Encrypted community report journal");
  }

  private assertAuthoritativeStorageUnchanged(): void {
    const snapshot = this.fileFingerprint(this.databasePath, "Encrypted community report database");
    const journal = this.fileFingerprint(this.journalPath, "Encrypted community report journal");
    if (!sameFingerprint(snapshot, this.snapshotFingerprint) || !sameFingerprint(journal, this.journalFingerprint)) {
      throw new Error("Encrypted community report storage changed outside the active aggregate writer.");
    }
  }
}

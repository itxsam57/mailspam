import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import { validateStoredCommunityDatabase } from "./aggregateState.js";
import { CommunityReportCapacityError, CommunityReportRateLimitError, CommunityReportValidationError } from "./errors.js";
import { COMMUNITY_STORAGE_KEY_BYTES, MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES } from "./resourceLimits.js";
import type {
  CommunityCampaignStatus,
  CommunityFeedPayload,
  CommunityIndicator,
  CommunityReportReceipt,
  CommunityReportSubmission,
} from "./types.js";

const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-community-reports-v1", "utf8");
const MAX_REPORTS_PER_REPORTER_PER_DAY = 50;
const MAX_CAMPAIGNS = 100_000;
const MAX_INDICATORS_PER_REPORT = 32;
const MAX_REPORT_AGE_MS = 30 * 24 * 60 * 60_000;
const MAX_FUTURE_SKEW_MS = 5 * 60_000;
const HUMAN_REPORT_BASE_WEIGHT = 5;
const REPORT_VERDICTS = new Set(["safe", "unknown", "review", "high_risk", "confirmed_threat"]);
const REPORT_INDICATOR_TYPES = new Set(["sender", "reply_to_domain", "url_domain", "attachment_hash", "campaign"]);
const ENVELOPE_WITHOUT_CIPHERTEXT_BYTES = Buffer.byteLength(JSON.stringify({
  version: 1,
  algorithm: ALGORITHM,
  iv: Buffer.alloc(12).toString("base64"),
  authTag: Buffer.alloc(16).toString("base64"),
  ciphertext: "",
}), "utf8");

interface ReporterRecord {
  /** Server acceptance time, never a client-controlled rate-limit timestamp. */
  reportedAt: string;
  evidenceScore: number;
  verdict: CommunityReportSubmission["verdict"];
}

interface CampaignRecord {
  firstSeen: string;
  lastSeen: string;
  reporters: Record<string, ReporterRecord>;
  indicatorReporters: Record<string, string[]>;
  evidenceCodes: Record<string, number>;
}

interface CommunityDatabase {
  version: 1;
  campaigns: Record<string, CampaignRecord>;
}

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
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
  confirmedStrongReporters: 3,
  confirmedWeight: 35,
};

function emptyDatabase(): CommunityDatabase {
  return { version: 1, campaigns: {} };
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(20, Number.isFinite(value) ? Math.round(value) : 0));
}

function verdictBonus(verdict: CommunityReportSubmission["verdict"]): number {
  switch (verdict) {
    case "confirmed_threat": return 8;
    case "high_risk": return 5;
    case "review": return 2;
    case "unknown": return 1;
    case "safe": return 0;
  }
}

function reporterWeight(record: ReporterRecord): number {
  return HUMAN_REPORT_BASE_WEIGHT + clampScore(record.evidenceScore) + verdictBonus(record.verdict);
}

function isStrong(record: ReporterRecord): boolean {
  return record.verdict === "confirmed_threat" || record.verdict === "high_risk" || record.evidenceScore >= 6;
}

function statusFor(record: CampaignRecord, thresholds: CommunityThresholds): CommunityCampaignStatus {
  const reporters = Object.values(record.reporters);
  const weight = reporters.reduce((sum, item) => sum + reporterWeight(item), 0);
  const strong = reporters.filter(isStrong).length;
  if (
    reporters.length >= thresholds.confirmedReporters &&
    strong >= thresholds.confirmedStrongReporters &&
    weight >= thresholds.confirmedWeight
  ) return "confirmed";
  if (reporters.length >= thresholds.warningReporters && weight >= thresholds.warningWeight) return "warning";
  return "candidate";
}

function indicatorKey(indicator: CommunityIndicator): string {
  return `${indicator.type}\0${indicator.value.toLowerCase()}`;
}

function parseIndicatorKey(key: string): CommunityIndicator | null {
  const separator = key.indexOf("\0");
  if (separator <= 0) return null;
  const type = key.slice(0, separator) as CommunityIndicator["type"];
  const value = key.slice(separator + 1);
  if (!value) return null;
  if (!["sender", "reply_to_domain", "url_domain", "attachment_hash", "campaign"].includes(type)) return null;
  return { type, value };
}

function ruleId(campaign: string, indicator: CommunityIndicator): string {
  return `community:${createHash("sha256").update(`${campaign}\0${indicator.type}\0${indicator.value}`).digest("hex").slice(0, 24)}`;
}

function encryptedEnvelopeByteLength(plaintextBytes: number): number {
  return ENVELOPE_WITHOUT_CIPHERTEXT_BYTES + (4 * Math.ceil(plaintextBytes / 3));
}

function validateSubmission(input: CommunityReportSubmission): CommunityReportSubmission {
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
  const now = Date.now();
  if (!Number.isFinite(reportedAt)) throw new CommunityReportValidationError("Report timestamp is invalid.");
  if (reportedAt > now + MAX_FUTURE_SKEW_MS || reportedAt < now - MAX_REPORT_AGE_MS) {
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
    evidenceCodes: [...new Set(input.evidenceCodes)],
    indicators,
  };
}

export class EncryptedCommunityAggregateStore {
  private readonly keyPath: string;
  private readonly databasePath: string;
  private keyCache: Buffer | null = null;

  constructor(
    private readonly dataDirectory: string,
    private readonly thresholds: CommunityThresholds = DEFAULT_COMMUNITY_THRESHOLDS,
  ) {
    this.keyPath = join(dataDirectory, "community-storage.key");
    this.databasePath = join(dataDirectory, "community-reports.enc.json");
  }

  accept(input: CommunityReportSubmission): CommunityReportReceipt {
    const report = validateSubmission(input);
    const database = this.readDatabase();
    const acceptedAt = new Date().toISOString();
    const nowMs = Date.parse(acceptedAt);
    const dayAgo = nowMs - 24 * 60 * 60_000;
    let reportsToday = 0;
    for (const campaign of Object.values(database.campaigns)) {
      const prior = campaign.reporters[report.reporterProof];
      if (prior && Date.parse(prior.reportedAt) >= dayAgo) reportsToday++;
    }

    const existing = database.campaigns[report.campaignFingerprint];
    const duplicate = Boolean(existing?.reporters[report.reporterProof]);
    if (!duplicate && reportsToday >= MAX_REPORTS_PER_REPORTER_PER_DAY) {
      throw new CommunityReportRateLimitError();
    }
    if (!existing && Object.keys(database.campaigns).length >= MAX_CAMPAIGNS) {
      throw new CommunityReportCapacityError();
    }

    const campaign: CampaignRecord = existing ?? {
      firstSeen: acceptedAt,
      lastSeen: acceptedAt,
      reporters: {},
      indicatorReporters: {},
      evidenceCodes: {},
    };
    const previousStatus = statusFor(campaign, this.thresholds);
    const previous = campaign.reporters[report.reporterProof];
    campaign.reporters[report.reporterProof] = {
      reportedAt: acceptedAt,
      evidenceScore: Math.max(previous?.evidenceScore ?? 0, report.evidenceScore),
      verdict: reporterWeight({ reportedAt: acceptedAt, evidenceScore: report.evidenceScore, verdict: report.verdict }) >=
        reporterWeight(previous ?? { reportedAt: acceptedAt, evidenceScore: 0, verdict: "safe" })
        ? report.verdict
        : previous!.verdict,
    };
    campaign.lastSeen = acceptedAt;

    for (const indicator of report.indicators) {
      const key = indicatorKey(indicator);
      const reporters = new Set(campaign.indicatorReporters[key] ?? []);
      reporters.add(report.reporterProof);
      campaign.indicatorReporters[key] = [...reporters].sort();
    }
    for (const code of report.evidenceCodes) {
      campaign.evidenceCodes[code] = (campaign.evidenceCodes[code] ?? 0) + (duplicate ? 0 : 1);
    }
    database.campaigns[report.campaignFingerprint] = campaign;
    this.writeDatabase(database);

    const status = statusFor(campaign, this.thresholds);
    return {
      accepted: true,
      duplicate,
      queued: false,
      campaignFingerprint: report.campaignFingerprint,
      independentReporters: Object.keys(campaign.reporters).length,
      status,
      feedUpdated: status !== previousStatus,
    };
  }

  buildFeedPayload(now = new Date()): CommunityFeedPayload {
    const database = this.readDatabase();
    const entries: SignedFeedEntry[] = [];
    for (const [fingerprint, campaign] of Object.entries(database.campaigns)) {
      const status = statusFor(campaign, this.thresholds);
      if (status === "candidate") continue;
      const minimumSupport = status === "confirmed"
        ? this.thresholds.confirmedReporters
        : this.thresholds.warningReporters;
      for (const [key, reporterProofs] of Object.entries(campaign.indicatorReporters)) {
        if (new Set(reporterProofs).size < minimumSupport) continue;
        const indicator = parseIndicatorKey(key);
        if (!indicator) continue;
        entries.push({
          type: indicator.type,
          value: indicator.value,
          confirmedThreat: status === "confirmed",
          ruleId: ruleId(fingerprint, indicator),
          independentReports: Object.keys(campaign.reporters).length,
          firstSeen: campaign.firstSeen,
          lastSeen: campaign.lastSeen,
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
    const database = this.readDatabase();
    let warnings = 0;
    let confirmed = 0;
    for (const campaign of Object.values(database.campaigns)) {
      const status = statusFor(campaign, this.thresholds);
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
      try {
        writeFileSync(this.keyPath, generated, { mode: 0o600, flag: "wx" });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      } finally {
        generated.fill(0);
      }
    }

    const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
    let descriptor: number;
    try {
      descriptor = openSync(this.keyPath, constants.O_RDONLY | noFollow);
    } catch {
      throw new Error("Community storage encryption key could not be opened safely.");
    }
    let key: Buffer;
    try {
      const stat = fstatSync(descriptor);
      if (!stat.isFile() || stat.size !== COMMUNITY_STORAGE_KEY_BYTES) {
        throw new Error("Community storage encryption key is invalid.");
      }
      key = readFileSync(descriptor);
      if (key.length !== COMMUNITY_STORAGE_KEY_BYTES) {
        key.fill(0);
        throw new Error("Community storage encryption key changed while being read.");
      }
    } finally {
      closeSync(descriptor);
    }
    try { chmodSync(this.keyPath, 0o600); } catch {}
    this.keyCache = key;
    return key;
  }

  private readDatabaseFile(): string {
    const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
    let descriptor: number;
    try {
      descriptor = openSync(this.databasePath, constants.O_RDONLY | noFollow);
    } catch {
      throw new Error("Encrypted community report database could not be opened safely.");
    }
    try {
      const stat = fstatSync(descriptor);
      if (!stat.isFile() || stat.size < 0 || stat.size > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) {
        throw new Error("Encrypted community report database exceeds the recoverable storage boundary.");
      }
      const content = readFileSync(descriptor);
      if (content.length > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) {
        content.fill(0);
        throw new Error("Encrypted community report database exceeded the recoverable storage boundary while being read.");
      }
      return content.toString("utf8");
    } finally {
      closeSync(descriptor);
    }
  }

  private readDatabase(): CommunityDatabase {
    if (!existsSync(this.databasePath)) return emptyDatabase();
    try {
      const envelope = JSON.parse(this.readDatabaseFile()) as EncryptedEnvelope;
      if (envelope.version !== 1 || envelope.algorithm !== ALGORITHM) throw new Error("Unsupported format.");
      const decipher = createDecipheriv(ALGORITHM, this.readKey(), Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      return validateStoredCommunityDatabase(JSON.parse(plaintext), MAX_CAMPAIGNS);
    } catch (error) {
      throw new Error(`Encrypted community report database could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private writeDatabase(database: CommunityDatabase): void {
    this.ensureDirectory();
    const plaintext = JSON.stringify(database);
    const plaintextBytes = Buffer.byteLength(plaintext, "utf8");
    if (encryptedEnvelopeByteLength(plaintextBytes) > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) {
      throw new CommunityReportCapacityError();
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.readKey(), iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      version: 1,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) {
      throw new CommunityReportCapacityError();
    }
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(5).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    try { renameSync(temporaryPath, this.databasePath); }
    catch {
      rmSync(this.databasePath, { force: true });
      renameSync(temporaryPath, this.databasePath);
    }
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }
}
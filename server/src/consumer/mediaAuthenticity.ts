import { createHash } from "node:crypto";

export type MediaAuthenticityState = "likely_manipulated" | "no_indicator" | "inconclusive" | "unavailable";

export interface MediaAuthenticityResult {
  schemaVersion: 1;
  state: MediaAuthenticityState;
  confidenceBand: "low" | "moderate" | "strong" | null;
  reasons: string[];
  checkedAt: string;
  detector: string | null;
  privacy: "explicit_user_submitted_media";
}

export interface MediaAuthenticityPort {
  analyze(input: {
    kind: "audio" | "image" | "video";
    bytes: Uint8Array;
    sha256: string;
    mimeType: string;
  }, signal: AbortSignal): Promise<Omit<MediaAuthenticityResult, "schemaVersion" | "checkedAt" | "privacy"> | null>;
}

export class UnconfiguredMediaAuthenticityPort implements MediaAuthenticityPort {
  async analyze(_input: { kind: "audio" | "image" | "video"; bytes: Uint8Array; sha256: string; mimeType: string }, signal: AbortSignal) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    return null;
  }
}

const MAX_AUDIO_BYTES = 10 * 1024 * 1024;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_VIDEO_BYTES = 25 * 1024 * 1024;

export async function analyzeMediaAuthenticity(input: {
  kind: "audio" | "image" | "video";
  bytes: Uint8Array;
  mimeType: string;
  port?: MediaAuthenticityPort;
  signal?: AbortSignal;
}): Promise<MediaAuthenticityResult> {
  if (!(input.bytes instanceof Uint8Array) || input.bytes.byteLength < 1) throw new Error("Media authenticity check requires local media bytes.");
  const limit = input.kind === "audio" ? MAX_AUDIO_BYTES : input.kind === "image" ? MAX_IMAGE_BYTES : MAX_VIDEO_BYTES;
  if (input.bytes.byteLength > limit) throw new Error(`Media authenticity input exceeds the bounded ${Math.floor(limit / 1024 / 1024)} MiB limit.`);
  if (typeof input.mimeType !== "string" || input.mimeType.length < 3 || input.mimeType.length > 128) throw new Error("Media MIME type is invalid.");
  const signal = input.signal ?? new AbortController().signal;
  const sha256 = createHash("sha256").update(input.bytes).digest("hex");
  const port = input.port ?? new UnconfiguredMediaAuthenticityPort();
  let result: Awaited<ReturnType<MediaAuthenticityPort["analyze"]>>;
  try {
    result = await port.analyze({ kind: input.kind, bytes: input.bytes, sha256, mimeType: input.mimeType }, signal);
  } catch (error) {
    return {
      schemaVersion: 1,
      state: "unavailable",
      confidenceBand: null,
      reasons: [`Media authenticity detector failed and was not interpreted as authentic: ${error instanceof Error ? error.message : String(error)}`],
      checkedAt: new Date().toISOString(),
      detector: null,
      privacy: "explicit_user_submitted_media",
    };
  }
  if (!result) {
    return {
      schemaVersion: 1,
      state: "unavailable",
      confidenceBand: null,
      reasons: ["No vetted local or explicitly consented media-authenticity detector is configured. Email Shield will not fabricate a deepfake verdict."],
      checkedAt: new Date().toISOString(),
      detector: null,
      privacy: "explicit_user_submitted_media",
    };
  }
  if (!["likely_manipulated", "no_indicator", "inconclusive", "unavailable"].includes(result.state)) throw new Error("Media authenticity detector returned an invalid state.");
  return {
    schemaVersion: 1,
    state: result.state,
    confidenceBand: result.confidenceBand,
    reasons: [...new Set(result.reasons.map((reason) => reason.trim()).filter(Boolean))].slice(0, 12),
    checkedAt: new Date().toISOString(),
    detector: result.detector,
    privacy: "explicit_user_submitted_media",
  };
}

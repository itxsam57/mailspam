import { createHash } from "node:crypto";
import type { CanonicalEnvelope, LinkInfo } from "../canonical/envelope.js";
import { analyzeHtmlInteractions } from "../util/htmlInteraction.js";
import {
  analyzeQrImages,
  isSupportedQrImageMimeType,
  MAX_QR_IMAGE_BYTES,
  type SupportedQrMimeType,
} from "../util/qrDecode.js";
import { normalizeRawMessage } from "../util/mimeNormalize.js";
import {
  evaluateConsumerScamEnvelope,
  type ConsumerScamCheckDependencies,
  type ConsumerScamCheckResponseV1,
} from "./scamCheck.js";

export const MAX_SUBMITTED_EML_BYTES = 4 * 1024 * 1024;
export const MAX_VISUAL_TEXT_CHARS = 64 * 1024;
const MAX_SUBMITTED_IMAGE_NAME_CHARS = 512;

export class ConsumerScamInputError extends Error {
  constructor(readonly code: "invalid_input" | "input_too_large" | "unsupported_image") {
    super(
      code === "input_too_large"
        ? "Submitted content exceeds the accepted local resource limit."
        : code === "unsupported_image"
          ? "Submitted image type is not supported for local Scam Check."
          : "Submitted Scam Check content is invalid.",
    );
    this.name = "ConsumerScamInputError";
  }
}

export interface VisualTextExtraction {
  text: string | null;
  /** False means the image could not be fully covered by the extractor. */
  complete: boolean;
  reason?: string;
}

/** Future native OCR bridge. Implementations must remain local unless separately consented. */
export interface VisualTextExtractor {
  extract(input: {
    content: Buffer;
    mimeType: SupportedQrMimeType;
    signal?: AbortSignal;
  }): Promise<VisualTextExtraction>;
}

export interface SubmittedImageInput {
  content: Buffer;
  mimeType: string;
  name?: string;
}

function validateBinaryInput(content: Buffer, maxBytes: number): void {
  if (!Buffer.isBuffer(content) || content.length === 0) throw new ConsumerScamInputError("invalid_input");
  if (content.length > maxBytes) throw new ConsumerScamInputError("input_too_large");
}

function normalizedImageName(value: string | undefined): string {
  const name = (value ?? "submitted-image").trim();
  if (!name || name.length > MAX_SUBMITTED_IMAGE_NAME_CHARS || /[\r\n\0]/.test(name)) {
    throw new ConsumerScamInputError("invalid_input");
  }
  return name;
}

function submittedIdentity(kind: string, content: Buffer): string {
  return createHash("sha256")
    .update(`email-shield-scam-check-${kind}-v1\0`, "utf8")
    .update(content)
    .digest("hex");
}

function forceSubmittedTransportUntrusted(envelope: CanonicalEnvelope): CanonicalEnvelope {
  // A user-controlled .eml can contain any Authentication-Results text it wants.
  // Preserve parsed values for explanation/forensics, but never grant them a
  // trusted provider provenance outside a connected provider acquisition path.
  return {
    ...envelope,
    authentication: {
      ...envelope.authentication,
      providerTrust: "unknown",
    },
  };
}

export async function evaluateSubmittedEml(
  content: Buffer,
  deps: ConsumerScamCheckDependencies = {},
): Promise<ConsumerScamCheckResponseV1> {
  validateBinaryInput(content, MAX_SUBMITTED_EML_BYTES);
  const id = submittedIdentity("eml", content);
  const normalized = await normalizeRawMessage(content, {
    provider: "imap",
    accountProof: `submitted-eml:${id}`,
    providerFolderName: "consumer-scam-check-eml",
    normalizedFolder: "other",
    providerNativeId: `submitted-eml:${id}`,
  });
  const envelope = forceSubmittedTransportUntrusted(normalized);
  return evaluateConsumerScamEnvelope(envelope, deps, [
    "Submitted .eml files are user-controlled artifacts. Authentication headers inside them are parsed as evidence but are never treated as trusted provider authentication provenance.",
  ]);
}

function boundedVisualText(extraction: VisualTextExtraction): { text: string | null; complete: boolean; limitations: string[] } {
  if (!extraction || typeof extraction !== "object") throw new ConsumerScamInputError("invalid_input");
  if (extraction.text !== null && typeof extraction.text !== "string") throw new ConsumerScamInputError("invalid_input");
  if (typeof extraction.complete !== "boolean") throw new ConsumerScamInputError("invalid_input");
  if (extraction.reason !== undefined && typeof extraction.reason !== "string") throw new ConsumerScamInputError("invalid_input");

  const raw = extraction.text?.trim() || null;
  const truncated = Boolean(raw && raw.length > MAX_VISUAL_TEXT_CHARS);
  const text = raw ? raw.slice(0, MAX_VISUAL_TEXT_CHARS) : null;
  const limitations: string[] = [];
  if (truncated) limitations.push(`Visual text was truncated to ${MAX_VISUAL_TEXT_CHARS} characters before local analysis.`);
  if (!extraction.complete) limitations.push(extraction.reason?.trim() || "Visual text extraction did not completely cover the submitted image.");
  return { text, complete: extraction.complete && !truncated, limitations };
}

function mergeLinks(primary: readonly LinkInfo[], secondary: readonly LinkInfo[]): LinkInfo[] {
  const seen = new Set<string>();
  const result: LinkInfo[] = [];
  for (const link of [...primary, ...secondary]) {
    const key = `${link.interaction ?? "navigation"}\0${link.normalizedUrl || link.rawUrl}\0${link.visibleText ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(link);
    if (result.length >= 256) break;
  }
  return result;
}

function buildImageEnvelope(params: {
  content: Buffer;
  mimeType: SupportedQrMimeType;
  name: string;
  visualText: string | null;
  visualTextComplete: boolean;
  visualLimitations: string[];
}): { envelope: CanonicalEnvelope; limitations: string[] } {
  const qr = analyzeQrImages([{ name: params.name, mimeType: params.mimeType, content: params.content }]);
  const visualInteractions = analyzeHtmlInteractions(null, params.visualText);
  const links = mergeLinks(qr.links, visualInteractions.links);
  const id = submittedIdentity("image", params.content);
  const parseNotes = [
    ...qr.incompleteReasons,
    ...visualInteractions.incompleteReasons,
    ...params.visualLimitations,
  ];
  if (!params.visualTextComplete) {
    parseNotes.push("Visible image text was not fully available to the local deterministic text-analysis layers.");
  }
  const incomplete = qr.incomplete || visualInteractions.incomplete || !params.visualTextComplete;

  const envelope: CanonicalEnvelope = {
    provider: "imap",
    accountProof: `submitted-image:${id}`,
    messageId: `submitted-image:${id}`,
    providerNativeId: `submitted-image:${id}`,
    folder: "other",
    providerFolderName: "consumer-scam-check-image",
    from: { displayName: null, address: null, domain: null },
    replyTo: null,
    subject: "",
    date: new Date(0).toISOString(),
    authentication: {
      spf: "unknown",
      dkim: "unknown",
      dmarc: "unknown",
      arc: "unknown",
      providerTrust: "unknown",
    },
    textPreview: params.visualText,
    htmlSignals: null,
    links,
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: incomplete ? "partial" : "complete",
    parseNotes,
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: params.content.length,
      // Canonical diagnostics describes message transfer encoding, not media type.
      encoding: "unknown",
      contentCoverage: incomplete ? "insufficient" : "complete",
      qrInspection: {
        supportedImages: 1,
        decodedUrlCount: qr.links.length,
        incomplete: qr.incomplete,
        incompleteReasons: [...qr.incompleteReasons],
      },
      attachmentHashInspection: {
        attachments: 0,
        hashed: 0,
        incomplete: false,
        incompleteReasons: [],
      },
    },
  };

  const limitations = [...params.visualLimitations];
  if (!params.visualTextComplete) {
    limitations.push("Image QR codes are checked locally, but visible screenshot/image text is not considered fully inspected unless a supported local visual-text extractor is available.");
  }
  if (qr.incomplete) limitations.push(...qr.incompleteReasons);
  if (visualInteractions.incomplete) limitations.push(...visualInteractions.incompleteReasons);
  return { envelope, limitations };
}

export async function evaluateSubmittedImage(
  input: SubmittedImageInput,
  deps: ConsumerScamCheckDependencies = {},
  options: { visualTextExtractor?: VisualTextExtractor; signal?: AbortSignal } = {},
): Promise<ConsumerScamCheckResponseV1> {
  if (!input || typeof input !== "object") throw new ConsumerScamInputError("invalid_input");
  validateBinaryInput(input.content, MAX_QR_IMAGE_BYTES);
  if (!isSupportedQrImageMimeType(input.mimeType)) throw new ConsumerScamInputError("unsupported_image");
  const name = normalizedImageName(input.name);

  let visual = {
    text: null as string | null,
    complete: false,
    limitations: ["No supported local visual-text extractor was available for this image."],
  };
  if (options.visualTextExtractor) {
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    visual = boundedVisualText(await options.visualTextExtractor.extract({
      content: input.content,
      mimeType: input.mimeType,
      signal: options.signal,
    }));
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
  }

  const built = buildImageEnvelope({
    content: input.content,
    mimeType: input.mimeType,
    name,
    visualText: visual.text,
    visualTextComplete: visual.complete,
    visualLimitations: visual.limitations,
  });
  return evaluateConsumerScamEnvelope(built.envelope, deps, built.limitations);
}

/**
 * Canonical Message Envelope
 *
 * Every adapter (Gmail, iCloud, Outlook, Yahoo, generic IMAP, and their
 * fixture equivalents) MUST normalize provider-native messages into this
 * exact shape before the detection engine ever sees them.
 *
 * Rule (spec Section 4): provider differences live inside adapters, never
 * inside the detection engine. No adapter may skip fields silently — use
 * `parseStatus` + `parseNotes` to surface partial/malformed/inaccessible
 * content instead of dropping it.
 */

export type Provider = "gmail" | "icloud" | "outlook" | "yahoo" | "imap";

export type ParseStatus = "complete" | "partial" | "malformed" | "inaccessible" | "skipped";

export type NormalizedFolder =
  | "inbox"
  | "spam"
  | "sent"
  | "drafts"
  | "trash"
  | "archive"
  | "other";

export interface AuthenticationSignals {
  spf: "pass" | "fail" | "softfail" | "neutral" | "none" | "unknown";
  dkim: "pass" | "fail" | "none" | "unknown";
  dmarc: "pass" | "fail" | "none" | "unknown";
  arc: "pass" | "fail" | "none" | "unknown";
  /** Provider's own trust/authenticity signal, if it exposes one (e.g. Gmail's own auth results header). */
  providerTrust?: "trusted" | "suspicious" | "unknown";
  /** Raw Authentication-Results header, kept for evidence citation only — never sent to global intelligence. */
  rawHeader?: string;
}

export interface FromField {
  displayName: string | null;
  address: string | null;
  domain: string | null;
}

export interface LinkInfo {
  /** Exact visible anchor text as rendered to the user. */
  visibleText: string | null;
  /** Raw href/URL exactly as found in the message. */
  rawUrl: string;
  /** Normalized (lowercased host, punycode-decoded, trailing slash stripped, etc). */
  normalizedUrl: string;
  /** Brand the link claims to represent, if the surrounding text/domain implies one (e.g. "paypal"). */
  claimedBrand: string | null;
  /** Whether normalizedUrl's registrable domain matches an official domain for claimedBrand. */
  brandDomainMismatch: boolean | null;
}

export interface AttachmentInfo {
  name: string;
  mimeType: string;
  sizeBytes: number;
  extension: string | null;
  /** Present only when the attachment was safe/small enough to hash locally. Never the file content itself. */
  sha256: string | null;
  /** True if filename shows a double extension pattern (invoice.pdf.exe) or other disguise pattern. */
  suspiciousNamePattern: boolean;
}

export interface ListHeaders {
  listId: string | null;
  listUnsubscribe: string | null;
  listUnsubscribePost: string | null; // RFC 8058 one-click marker
}

export interface ThreadContext {
  /** True if this sender has no prior successful exchange in local history. */
  isFirstContact: boolean;
  /** True if this message claims to continue a thread whose Message-Id/References chain doesn't actually match locally known history. */
  threadContinuityBroken: boolean;
  /** True if reply-to changed mid-thread relative to prior messages in the same thread, per local history. */
  replyToChangedMidThread: boolean;
}

export interface CanonicalEnvelope {
  // --- identity ---
  provider: Provider;
  accountProof: string; // one-way hash, never the raw mailbox address
  messageId: string;
  /**
   * The provider's own native message identifier (Gmail message id, IMAP
   * UID+mailbox, Graph message id, etc), needed for action calls like
   * moveToTrash. This is deliberately separate from `messageId` (the
   * RFC822 Message-ID), which is what cross-folder/cross-provider
   * deduplication and dashboard identity use — the two are not
   * interchangeable and conflating them was a real bug caught while
   * wiring the Gmail/IMAP adapters' moveToTrash implementations.
   */
  providerNativeId: string;

  // --- location ---
  folder: NormalizedFolder;
  providerFolderName: string;

  // --- headers ---
  from: FromField;
  replyTo: FromField | null;
  subject: string; // MIME-decoded, Unicode
  date: string; // ISO 8601, normalized to UTC

  // --- trust signals ---
  authentication: AuthenticationSignals;

  // --- content (memory-only, bounded) ---
  textPreview: string | null; // bounded decoded body text
  htmlSignals: {
    extractedText: string | null;
    hrefs: string[];
    hasForm: boolean;
    hasPasswordField: boolean;
  } | null;

  // --- structural indicators ---
  links: LinkInfo[];
  attachments: AttachmentInfo[];
  listHeaders: ListHeaders;
  threadContext: ThreadContext;

  // --- parse integrity (spec Section 7: never present "Safe" for partial content) ---
  parseStatus: ParseStatus;
  parseNotes: string[]; // human-readable reasons for any non-"complete" status

  // --- diagnostics (redacted, no secrets/PII beyond what's above) ---
  diagnostics: {
    fetchedAt: string;
    sizeBytes: number;
    encoding: "plain" | "base64" | "quoted-printable" | "multipart" | "mixed" | "unknown";
  };
}

/**
 * Every adapter must be able to produce this for a raw provider message.
 * Adapters throw only for true transport failures (network down); anything
 * about the *message itself* being weird must map to parseStatus, not a throw.
 */
export type NormalizeFn<TRaw> = (raw: TRaw, accountProof: string) => CanonicalEnvelope;

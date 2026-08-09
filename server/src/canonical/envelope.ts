/**
 * Canonical Message Envelope
 *
 * Every adapter (Gmail, iCloud, Outlook, Yahoo, generic IMAP, and their
 * fixture equivalents) MUST normalize provider-native messages into this
 * exact shape before the detection engine ever sees them.
 */

export type Provider = "gmail" | "icloud" | "outlook" | "yahoo" | "imap";
export type ParseStatus = "complete" | "partial" | "malformed" | "inaccessible" | "skipped";
export type ContentCoverage = "complete" | "bounded_sufficient" | "insufficient";

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
  providerTrust?: "trusted" | "suspicious" | "unknown";
  rawHeader?: string;
}

export interface FromField {
  displayName: string | null;
  address: string | null;
  domain: string | null;
}

export interface LinkInfo {
  visibleText: string | null;
  rawUrl: string;
  normalizedUrl: string;
  claimedBrand: string | null;
  brandDomainMismatch: boolean | null;
}

export interface AttachmentInfo {
  name: string;
  mimeType: string;
  sizeBytes: number;
  extension: string | null;
  sha256: string | null;
  suspiciousNamePattern: boolean;
}

export interface ListHeaders {
  listId: string | null;
  listUnsubscribe: string | null;
  listUnsubscribePost: string | null;
}

export interface ThreadContext {
  isFirstContact: boolean;
  threadContinuityBroken: boolean;
  replyToChangedMidThread: boolean;
  /**
   * Ephemeral, account-local scan evidence. True only after the same normalized
   * sender address has already appeared earlier in the current scan. It is
   * never persisted, uploaded, or used as a sender allowlist.
   */
  senderPreviouslySeenInScan?: boolean;
  /** Aggregate local history only; no raw historical sender/message identity is carried here. */
  relationshipPriorMessages?: number;
  relationshipPriorAuthenticatedMessages?: number;
  relationshipPriorSafeMessages?: number;
  relationshipPriorSuspiciousMessages?: number;
  /** True only after a conservative prior-history threshold; never an allowlist. */
  hasEstablishedSenderHistory?: boolean;
  /** Prior established authenticated history followed by an explicit current authentication failure. */
  relationshipAuthenticationDowngrade?: boolean;
  /** A previously stable non-empty Reply-To fingerprint changed for an established sender. */
  replyToChangedFromRelationshipHistory?: boolean;
}

export interface CanonicalEnvelope {
  provider: Provider;
  accountProof: string;
  messageId: string;
  providerNativeId: string;

  folder: NormalizedFolder;
  providerFolderName: string;

  from: FromField;
  replyTo: FromField | null;
  subject: string;
  date: string;

  authentication: AuthenticationSignals;

  textPreview: string | null;
  htmlSignals: {
    extractedText: string | null;
    hrefs: string[];
    hasForm: boolean;
    hasPasswordField: boolean;
  } | null;

  links: LinkInfo[];
  attachments: AttachmentInfo[];
  listHeaders: ListHeaders;
  threadContext: ThreadContext;

  parseStatus: ParseStatus;
  parseNotes: string[];

  diagnostics: {
    fetchedAt: string;
    sizeBytes: number;
    encoding: "plain" | "base64" | "quoted-printable" | "multipart" | "mixed" | "unknown";
    /**
     * `bounded_sufficient` means a provider body was deliberately capped for
     * performance, but enough decoded visible text was available for the
     * deterministic layers to run. It is not the same as silently missing a
     * body, attachment, or unreadable MIME part.
     */
    contentCoverage: ContentCoverage;
  };
}

export type NormalizeFn<TRaw> = (raw: TRaw, accountProof: string) => CanonicalEnvelope;
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
  /** Body/HTML link vs a URL decoded locally from a bounded QR-capable image. */
  source?: "body" | "qr";
  /** How body HTML invokes this destination; QR/plain links are ordinary navigation. */
  interaction?: "navigation" | "form_action" | "automatic_redirect";
}

export type AttachmentMagicType = "pe_executable" | "elf_executable" | "zip" | "pdf" | "png" | "jpeg" | "ole_compound" | "rtf" | "text_or_unknown";

export interface ArchiveSecurityInspection {
  format: "zip";
  entryCount: number;
  encryptedEntries: number;
  executableOrScriptEntries: number;
  macroCapableEntries: number;
  nestedArchiveEntries: number;
  declaredCompressedBytes: number;
  declaredUncompressedBytes: number;
  maximumCompressionRatio: number;
  overResourceLimit: boolean;
  incomplete: boolean;
  reasons: string[];
}

export interface AttachmentSecurityInspection {
  magicType: AttachmentMagicType;
  extensionMismatch: boolean;
  executableOrScript: boolean;
  macroCapable: boolean;
  archive: ArchiveSecurityInspection | null;
  incomplete: boolean;
  reasons: string[];
}

export interface AttachmentInfo {
  name: string;
  mimeType: string;
  sizeBytes: number;
  extension: string | null;
  /** SHA-256 of the complete locally decoded attachment bytes, or null when those bytes were not safely available. */
  sha256: string | null;
  suspiciousNamePattern: boolean;
  /** Transient-byte local static inspection; contains metadata only, never attachment bytes. */
  securityInspection?: AttachmentSecurityInspection;
}

export interface ListHeaders {
  listId: string | null;
  listUnsubscribe: string | null;
  listUnsubscribePost: string | null;
  /** True only when bounded raw MIME contains exactly one field of each RFC 8058 list-header type. */
  oneClickHeaderSetUnambiguous?: boolean;
  /**
   * Worker/server-only bounded DKIM signature identities used for RFC 8058
   * correlation. Every parseable raw signature candidate is retained so a
   * duplicate `d=`+`s=` identity cannot be hidden merely because only one
   * copy signs the required list headers. Raw signature bytes/values and the
   * full signed-header list are never retained.
   */
  oneClickDkimSignatures?: Array<{
    domain: string;
    selector: string;
    coversRequiredHeaders: boolean;
  }>;
}

export interface ThreadContext {
  isFirstContact: boolean;
  threadContinuityBroken: boolean;
  replyToChangedMidThread: boolean;
  /**
   * Worker-only bounded RFC threading identifiers extracted during MIME
   * normalization. Relationship-history annotation MUST consume and delete
   * this field before scoring or browser serialization. These raw identifiers
   * are never persisted.
   */
  pendingThreadReferences?: {
    inReplyTo: string | null;
    references: string[];
  };
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
    /** Privacy-reduced QR inspection status; never contains image bytes or QR payload text. */
    qrInspection?: {
      supportedImages: number;
      decodedUrlCount: number;
      incomplete: boolean;
      incompleteReasons: string[];
    };
    /**
     * Privacy-reduced exact-hash coverage. This records only counts and generic
     * reasons; attachment bytes are transient and attachment names must not be
     * copied into this diagnostic object.
     */
    attachmentHashInspection?: {
      attachments: number;
      hashed: number;
      incomplete: boolean;
      incompleteReasons: string[];
    };
    /** Privacy-reduced local static/archive inspection coverage. */
    attachmentSecurityInspection?: {
      inspected: number;
      incomplete: number;
      encryptedArchives: number;
      resourceLimitedArchives: number;
    };
  };
}

export type NormalizeFn<TRaw> = (raw: TRaw, accountProof: string) => CanonicalEnvelope;

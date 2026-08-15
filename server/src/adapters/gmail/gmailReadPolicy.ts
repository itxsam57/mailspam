const RETRYABLE_GMAIL_REASONS = new Set([
  "rateLimitExceeded",
  "userRateLimitExceeded",
  "backendError",
]);

const RETRYABLE_NETWORK_CODES = new Set([
  "ECONNRESET",
  "EAI_AGAIN",
  "ENETDOWN",
  "ENETRESET",
  "ENETUNREACH",
  "ETIMEDOUT",
]);

const RETRYABLE_HTTP_STATUS = new Set([429, 500, 502, 503, 504]);

export const GMAIL_MESSAGE_GET_MIN_SPACING_MS = 300;
const GMAIL_RETRY_BASE_DELAY_MS = 1_000;
const GMAIL_RETRY_JITTER_MS = 250;
const GMAIL_READ_MAX_ATTEMPTS = 6;

interface GmailErrorShape {
  code?: unknown;
  status?: unknown;
  response?: {
    status?: unknown;
    data?: {
      error?: {
        code?: unknown;
        message?: unknown;
        errors?: Array<{ reason?: unknown }>;
      };
    };
  };
}

function numericStatus(error: unknown): number | null {
  if (!error || typeof error !== "object") return null;
  const candidate = error as GmailErrorShape;
  for (const value of [candidate.response?.status, candidate.status, candidate.response?.data?.error?.code, candidate.code]) {
    const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
    if (Number.isInteger(numeric) && numeric >= 100 && numeric <= 599) return numeric;
  }
  return null;
}

function gmailReasons(error: unknown): string[] {
  if (!error || typeof error !== "object") return [];
  const reasons = (error as GmailErrorShape).response?.data?.error?.errors ?? [];
  return reasons
    .map((item) => typeof item.reason === "string" ? item.reason : "")
    .filter(Boolean);
}

function networkCode(error: unknown): string | null {
  if (!error || typeof error !== "object") return null;
  const code = (error as GmailErrorShape).code;
  return typeof code === "string" ? code.toUpperCase() : null;
}

export function isMissingGmailMessageError(error: unknown): boolean {
  const status = numericStatus(error);
  return status === 404 || status === 410;
}

export function isRetryableGmailReadError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "AbortError") return false;
  const status = numericStatus(error);
  if (status !== null && RETRYABLE_HTTP_STATUS.has(status)) return true;
  if (status === 403 && gmailReasons(error).some((reason) => RETRYABLE_GMAIL_REASONS.has(reason))) return true;
  const code = networkCode(error);
  return Boolean(code && RETRYABLE_NETWORK_CODES.has(code));
}

export async function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  if (ms <= 0) return;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export interface GmailReadRetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  jitterMs?: number;
  random?: () => number;
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
  beforeAttempt?: (attempt: number) => Promise<void>;
}

export async function runGmailReadWithBackoff<T>(
  operation: (attempt: number) => Promise<T>,
  signal: AbortSignal,
  options: GmailReadRetryOptions = {},
): Promise<T> {
  const maxAttempts = Math.max(1, Math.floor(options.maxAttempts ?? GMAIL_READ_MAX_ATTEMPTS));
  const baseDelayMs = Math.max(0, Math.floor(options.baseDelayMs ?? GMAIL_RETRY_BASE_DELAY_MS));
  const jitterMs = Math.max(0, Math.floor(options.jitterMs ?? GMAIL_RETRY_JITTER_MS));
  const random = options.random ?? Math.random;
  const delay = options.delay ?? abortableDelay;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    await options.beforeAttempt?.(attempt);
    try {
      return await operation(attempt);
    } catch (error) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      if (attempt >= maxAttempts || !isRetryableGmailReadError(error)) throw error;
      const exponential = baseDelayMs * (2 ** (attempt - 1));
      const jitter = jitterMs > 0 ? Math.floor(Math.max(0, Math.min(1, random())) * jitterMs) : 0;
      await delay(exponential + jitter, signal);
    }
  }

  throw new Error("Gmail read retry policy exhausted unexpectedly.");
}

export interface GmailQuotaPacerOptions {
  minimumSpacingMs?: number;
  now?: () => number;
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
}

/**
 * Gmail projects created after May 1, 2026 receive a 6,000 quota-unit/user/minute
 * budget, while messages.get costs 20 units. Starting message-body reads at most
 * once every 300 ms caps this scanner near 4,000 message-get units/minute and
 * leaves headroom for list/profile calls and bounded retries.
 */
export class GmailMessageReadPacer {
  private tail: Promise<void> = Promise.resolve();
  private nextStartAt = 0;
  private readonly minimumSpacingMs: number;
  private readonly now: () => number;
  private readonly delay: (ms: number, signal: AbortSignal) => Promise<void>;

  constructor(options: GmailQuotaPacerOptions = {}) {
    this.minimumSpacingMs = Math.max(0, Math.floor(options.minimumSpacingMs ?? GMAIL_MESSAGE_GET_MIN_SPACING_MS));
    this.now = options.now ?? Date.now;
    this.delay = options.delay ?? abortableDelay;
  }

  async wait(signal: AbortSignal): Promise<void> {
    let release!: () => void;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;

    try {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const waitMs = Math.max(0, this.nextStartAt - this.now());
      if (waitMs > 0) await this.delay(waitMs, signal);
      const startedAt = Math.max(this.nextStartAt, this.now());
      this.nextStartAt = startedAt + this.minimumSpacingMs;
    } finally {
      release();
    }
  }
}

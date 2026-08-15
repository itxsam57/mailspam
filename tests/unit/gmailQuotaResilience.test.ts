import { describe, expect, it, vi } from "vitest";
import {
  GMAIL_MESSAGE_GET_MIN_SPACING_MS,
  GmailMessageReadPacer,
  isMissingGmailMessageError,
  isRetryableGmailReadError,
  runGmailReadWithBackoff,
} from "../../server/src/adapters/gmail/gmailReadPolicy.js";

function gmailError(status: number, reason?: string) {
  return {
    response: {
      status,
      data: {
        error: {
          code: status,
          errors: reason ? [{ reason }] : [],
        },
      },
    },
  };
}

describe("Gmail quota-aware read policy", () => {
  it("retries only Gmail rate/server failures and leaves auth/not-found failures fail-fast", () => {
    expect(isRetryableGmailReadError(gmailError(429))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(500))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(502))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(503))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(504))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(403, "rateLimitExceeded"))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(403, "userRateLimitExceeded"))).toBe(true);
    expect(isRetryableGmailReadError(gmailError(401))).toBe(false);
    expect(isRetryableGmailReadError(gmailError(403, "domainPolicy"))).toBe(false);
    expect(isRetryableGmailReadError(gmailError(404))).toBe(false);
    expect(isRetryableGmailReadError(gmailError(410))).toBe(false);
    expect(isMissingGmailMessageError(gmailError(404))).toBe(true);
    expect(isMissingGmailMessageError(gmailError(410))).toBe(true);
  });

  it("uses bounded exponential backoff without retrying successful or non-retryable reads", async () => {
    const signal = new AbortController().signal;
    const delays: number[] = [];
    let attempts = 0;
    const result = await runGmailReadWithBackoff(
      async () => {
        attempts += 1;
        if (attempts < 3) throw gmailError(429);
        return "ok";
      },
      signal,
      {
        maxAttempts: 4,
        baseDelayMs: 1_000,
        jitterMs: 0,
        delay: async (ms) => { delays.push(ms); },
      },
    );

    expect(result).toBe("ok");
    expect(attempts).toBe(3);
    expect(delays).toEqual([1_000, 2_000]);

    const failFast = vi.fn(async () => { throw gmailError(401); });
    await expect(runGmailReadWithBackoff(failFast, signal, {
      delay: async () => { throw new Error("delay should not run"); },
    })).rejects.toEqual(gmailError(401));
    expect(failFast).toHaveBeenCalledTimes(1);
  });

  it("serializes message-get starts so the scanner stays below the new per-user Gmail quota", async () => {
    let now = 0;
    const waits: number[] = [];
    const pacer = new GmailMessageReadPacer({
      now: () => now,
      delay: async (ms) => {
        waits.push(ms);
        now += ms;
      },
    });
    const signal = new AbortController().signal;

    await Promise.all([
      pacer.wait(signal),
      pacer.wait(signal),
      pacer.wait(signal),
      pacer.wait(signal),
    ]);

    expect(GMAIL_MESSAGE_GET_MIN_SPACING_MS).toBe(300);
    expect(waits).toEqual([300, 300, 300]);
    // 20 quota units per messages.get at 300 ms spacing is about 4,000 units/minute,
    // leaving material headroom below Google's 6,000 user/project minute budget.
    expect((60_000 / GMAIL_MESSAGE_GET_MIN_SPACING_MS) * 20).toBe(4_000);
  });

  it("honors cancellation during backoff/pacing instead of hiding it as an inaccessible message", async () => {
    const controller = new AbortController();
    controller.abort();
    const operation = vi.fn(async () => "should-not-run");
    await expect(runGmailReadWithBackoff(operation, controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(operation).not.toHaveBeenCalled();

    const pacer = new GmailMessageReadPacer();
    await expect(pacer.wait(controller.signal)).rejects.toMatchObject({ name: "AbortError" });
  });
});

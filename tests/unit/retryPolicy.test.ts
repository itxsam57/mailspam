import { describe, expect, it, vi } from "vitest";
import { runWithSingleRetry, isRetryableScanError } from "../../server/src/workers/retryPolicy.js";
import { ImapCommandTimeoutError } from "../../server/src/adapters/imap/imapAdapter.js";

describe("scan retry policy", () => {
  it("retries one transient IMAP timeout exactly once", async () => {
    const operation = vi.fn(async (attempt: 1 | 2) => {
      if (attempt === 1) throw new ImapCommandTimeoutError("folder discovery", 20_000);
      return "ok";
    });
    const onRetry = vi.fn();

    await expect(runWithSingleRetry(operation, onRetry)).resolves.toBe("ok");
    expect(operation).toHaveBeenCalledTimes(2);
    expect(operation).toHaveBeenNthCalledWith(1, 1);
    expect(operation).toHaveBeenNthCalledWith(2, 2);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("does not retry ordinary provider, parse, or authentication errors", async () => {
    const operation = vi.fn(async () => { throw new Error("authentication failed"); });
    const onRetry = vi.fn();

    await expect(runWithSingleRetry(operation, onRetry)).rejects.toThrow("authentication failed");
    expect(operation).toHaveBeenCalledTimes(1);
    expect(onRetry).not.toHaveBeenCalled();
  });

  it("does not retry user cancellation", () => {
    expect(isRetryableScanError(new DOMException("Aborted", "AbortError"))).toBe(false);
  });

  it("lets the retry guard stop replay after progress has already been emitted", async () => {
    const timeout = new ImapCommandTimeoutError("metadata fetch", 30_000);
    const operation = vi.fn(async () => { throw timeout; });
    const onRetry = vi.fn(async () => { throw timeout; });

    await expect(runWithSingleRetry(operation, onRetry)).rejects.toBe(timeout);
    expect(operation).toHaveBeenCalledTimes(1);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

import { describe, expect, it } from "vitest";
import {
  ImapCommandTimeoutError,
  withImapDeadline,
} from "../../server/src/adapters/imap/imapAdapter.js";

describe("IMAP command deadlines", () => {
  it("reports the exact stage and timeout instead of a generic command error", async () => {
    const controller = new AbortController();
    const never = new Promise<string>(() => {});

    await expect(
      withImapDeadline(never, controller.signal, "metadata fetch for 10 messages in Junk", 5),
    ).rejects.toMatchObject({
      name: "ImapCommandTimeoutError",
      code: "IMAP_TIMEOUT",
      stage: "metadata fetch for 10 messages in Junk",
      timeoutMs: 5,
      message: "IMAP metadata fetch for 10 messages in Junk exceeded 5ms deadline",
    });
  });

  it("uses AbortError for user cancellation rather than calling it a timeout", async () => {
    const controller = new AbortController();
    const never = new Promise<string>(() => {});
    const pending = withImapDeadline(never, controller.signal, "UID search", 1000);
    controller.abort();

    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });

  it("exposes a stable timeout error type", () => {
    const error = new ImapCommandTimeoutError("connection", 25_000);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("ImapCommandTimeoutError");
    expect(error.code).toBe("IMAP_TIMEOUT");
  });
});

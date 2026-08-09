import { describe, expect, it } from "vitest";
import {
  extractThreadMessageIds,
  normalizeHeaderText,
  normalizeRawMessage,
  parseAuthResultsHeader,
} from "../../server/src/util/mimeNormalize.js";

describe("provider header normalization", () => {
  it("accepts string, Buffer, array, and structured header values", () => {
    expect(normalizeHeaderText("spf=pass")).toBe("spf=pass");
    expect(normalizeHeaderText(Buffer.from("dkim=fail", "utf8"))).toBe("dkim=fail");
    expect(normalizeHeaderText(["spf=pass", Buffer.from("dmarc=pass")])).toBe("spf=pass; dmarc=pass");
    expect(normalizeHeaderText({ value: "arc=pass" })).toBe("arc=pass");
    expect(normalizeHeaderText({ text: "spf=neutral" })).toBe("spf=neutral");
  });

  it("never calls string methods on a non-string authentication header", () => {
    const fromBuffer = parseAuthResultsHeader(Buffer.from("spf=pass; dkim=fail; dmarc=pass; arc=none"));
    expect(fromBuffer).toMatchObject({ spf: "pass", dkim: "fail", dmarc: "pass", arc: "none" });

    const fromArray = parseAuthResultsHeader(["spf=softfail", { value: "dkim=pass; dmarc=fail" }]);
    expect(fromArray).toMatchObject({ spf: "softfail", dkim: "pass", dmarc: "fail" });
  });

  it("returns unknown authentication signals for unusable values", () => {
    expect(parseAuthResultsHeader({})).toEqual({
      spf: "unknown",
      dkim: "unknown",
      dmarc: "unknown",
      arc: "unknown",
    });
  });

  it("keeps the newest bounded explicit RFC message identifiers", () => {
    const identifiers = Array.from({ length: 30 }, (_, index) => `<thread-${index}@example.test>`).join(" ");
    const extracted = extractThreadMessageIds(`noise ${identifiers} bare-id@example.test`);

    expect(extracted).toHaveLength(20);
    expect(extracted[0]).toBe("<thread-10@example.test>");
    expect(extracted.at(-1)).toBe("<thread-29@example.test>");
    expect(extracted).not.toContain("bare-id@example.test");
  });

  it("carries In-Reply-To and References only as transient thread context", async () => {
    const raw = [
      "From: Known Sender <known@example.test>",
      "To: user@example.test",
      "Subject: Re: routine thread",
      "Message-ID: <child@example.test>",
      "In-Reply-To: <parent@example.test>",
      "References: <root@example.test> <parent@example.test>",
      "Date: Mon, 10 Aug 2026 10:00:00 +0000",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Routine reply body.",
    ].join("\r\n");

    const envelope = await normalizeRawMessage(raw, {
      provider: "gmail",
      accountProof: "fixture-proof",
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "child-native",
    });

    expect(envelope.threadContext.pendingThreadReferences).toEqual({
      inReplyTo: "<parent@example.test>",
      references: ["<root@example.test>", "<parent@example.test>"],
    });
  });
});

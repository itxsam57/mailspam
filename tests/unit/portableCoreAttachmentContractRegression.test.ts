import { describe, expect, it } from "vitest";
import { evaluatePortableCore, PortableCoreContractError } from "../../server/src/core/portableCore.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";

const attachmentMessage = [
  "From: sender@example.test",
  "To: recipient@example.test",
  "Subject: Attachment contract regression",
  "Message-ID: <portable-attachment@example.test>",
  "MIME-Version: 1.0",
  "Content-Type: multipart/mixed; boundary=portable-boundary",
  "",
  "--portable-boundary",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Routine readable message body.",
  "--portable-boundary",
  "Content-Type: application/pdf; name=sample.pdf",
  "Content-Disposition: attachment; filename=sample.pdf",
  "Content-Transfer-Encoding: base64",
  "",
  "JVBERi0xLjQKJSBwb3J0YWJsZSBjb3JlIGNvbnRyYWN0IHRlc3QK",
  "--portable-boundary--",
  "",
].join("\r\n");

async function request() {
  const envelope = await normalizeRawMessage(attachmentMessage, {
    provider: "gmail",
    accountProof: "portable-attachment-account-proof",
    providerFolderName: "INBOX",
    normalizedFolder: "inbox",
    providerNativeId: "portable-attachment-native-id",
  });
  return {
    schemaVersion: 1,
    envelope,
    personalPolicy: new InMemoryPersonalPolicyStore().snapshot(),
    intelligence: { state: "verified" as const, entries: [] },
  };
}

describe("portable core canonical attachment contract", () => {
  it("accepts the real canonical attachment security shape produced by MIME normalization", async () => {
    const candidate = await request();
    const inspection = candidate.envelope.attachments[0]?.securityInspection;

    expect(inspection).toBeDefined();
    expect(inspection?.staticMalware).toMatchObject({
      risk: expect.stringMatching(/^(none|suspicious|high)$/),
      indicators: expect.any(Array),
      coverage: expect.stringMatching(/^(full|sampled)$/),
    });
    expect(() => evaluatePortableCore(candidate)).not.toThrow();
  });

  it("keeps static-malware validation exact rather than accepting arbitrary values or fields", async () => {
    const invalidRisk = await request();
    invalidRisk.envelope.attachments[0]!.securityInspection!.staticMalware.risk = "critical" as never;
    expect(() => evaluatePortableCore(invalidRisk)).toThrow(PortableCoreContractError);

    const invalidIndicator = await request();
    invalidIndicator.envelope.attachments[0]!.securityInspection!.staticMalware.indicators = ["arbitrary_indicator"] as never;
    expect(() => evaluatePortableCore(invalidIndicator)).toThrow(PortableCoreContractError);

    const extraField = await request();
    Object.assign(extraField.envelope.attachments[0]!.securityInspection!.staticMalware, { rawMatch: "must-not-enter-core" });
    expect(() => evaluatePortableCore(extraField)).toThrow(PortableCoreContractError);
  });
});

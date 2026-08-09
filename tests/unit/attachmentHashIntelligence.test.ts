import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { buildCommunityReportContext } from "../../server/src/community/fingerprint.js";
import { globalIntelligenceLayer } from "../../server/src/engine/layers/globalIntelligence.js";
import type { ScoredMessage } from "../../server/src/engine/verdict.js";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";

function sha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function rawWithAttachment(content: Buffer): Buffer {
  const boundary = "email-shield-attachment-hash-test";
  return Buffer.from([
    "From: Example Sender <sender@example.test>",
    "To: user@example.test",
    "Subject: Attached document",
    "Message-ID: <attachment-hash-test@example.test>",
    "Date: Mon, 10 Aug 2026 10:00:00 +0000",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "MIME-Version: 1.0",
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Please review the attached document.",
    `--${boundary}`,
    "Content-Type: application/octet-stream; name=" + '"payload.bin"',
    "Content-Disposition: attachment; filename=" + '"payload.bin"',
    "Content-Transfer-Encoding: base64",
    "",
    content.toString("base64"),
    `--${boundary}--`,
    "",
  ].join("\r\n"), "utf8");
}

async function normalizedAttachmentEnvelope(content = Buffer.from("exact malicious attachment bytes", "utf8")): Promise<CanonicalEnvelope> {
  return normalizeRawMessage(rawWithAttachment(content), {
    provider: "gmail",
    accountProof: "proof",
    providerFolderName: "INBOX",
    normalizedFolder: "inbox",
    providerNativeId: "native-attachment-hash",
  });
}

function scored(verdict: ScoredMessage["verdict"] = "high_risk"): ScoredMessage {
  return {
    score: 6,
    evidence: [{
      layer: "attachment_qr",
      code: "TEST_ATTACHMENT_EVIDENCE",
      description: "Synthetic local evidence.",
      scoreContribution: 6,
      source: "local",
    }],
    verdict,
    confirmedByRule: false,
    layerResults: [],
  };
}

describe("attachment hash intelligence", () => {
  it("hashes the complete decoded MIME attachment bytes during raw-message normalization", async () => {
    const content = Buffer.from("complete decoded payload bytes", "utf8");
    const envelope = await normalizedAttachmentEnvelope(content);

    expect(envelope.attachments).toHaveLength(1);
    expect(envelope.attachments[0]?.sha256).toBe(sha256(content));
    expect(envelope.diagnostics.attachmentHashInspection).toEqual({
      attachments: 1,
      hashed: 1,
      incomplete: false,
      incompleteReasons: [],
    });
  });

  it("activates an exact confirmed signed attachment-hash rule", async () => {
    const content = Buffer.from("known confirmed threat attachment", "utf8");
    const envelope = await normalizedAttachmentEnvelope(content);
    const expected = sha256(content);
    const { result, confirmedByGlobalRule } = globalIntelligenceLayer(envelope, {
      getVerifiedEntries: () => [{
        type: "attachment_hash",
        value: expected,
        confirmedThreat: true,
        ruleId: "attachment-rule-1",
        independentReports: 5,
      }],
    });

    expect(confirmedByGlobalRule).toBe(true);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "GLOBAL_CONFIRMED_MATCH",
        source: "signed_feed",
        scoreContribution: 10,
      }),
    ]));
    expect(result.incomplete).toBe(false);
  });

  it("includes only the hash, never attachment name or bytes, in community report context", async () => {
    const content = Buffer.from("private attachment body that must not leave the client", "utf8");
    const envelope = await normalizedAttachmentEnvelope(content);
    envelope.attachments[0]!.name = "private-customer-contract.pdf";

    const context = buildCommunityReportContext(envelope, scored());
    const serialized = JSON.stringify(context);

    expect(context.indicators).toContainEqual({ type: "attachment_hash", value: sha256(content) });
    expect(serialized).not.toContain("private-customer-contract.pdf");
    expect(serialized).not.toContain("private attachment body");
  });

  it("blocks an automatic Safe decision when signed attachment-hash rules exist but coverage is incomplete", async () => {
    const envelope = await normalizedAttachmentEnvelope();
    envelope.attachments[0]!.sha256 = null;
    envelope.diagnostics.attachmentHashInspection = {
      attachments: 1,
      hashed: 0,
      incomplete: true,
      incompleteReasons: ["bounded"],
    };

    const { result } = globalIntelligenceLayer(envelope, {
      getVerifiedEntries: () => [{
        type: "attachment_hash",
        value: "a".repeat(64),
        confirmedThreat: true,
        ruleId: "attachment-rule-2",
      }],
    });

    expect(result.incomplete).toBe(true);
    expect(result.blocksSafeVerdict).toBe(true);
    expect(result.evidence).toEqual([]);
  });

  it("does not create unrelated incompleteness when the verified feed has no attachment-hash rules", async () => {
    const envelope = await normalizedAttachmentEnvelope();
    envelope.attachments[0]!.sha256 = null;
    envelope.diagnostics.attachmentHashInspection = {
      attachments: 1,
      hashed: 0,
      incomplete: true,
      incompleteReasons: ["bounded"],
    };

    const { result } = globalIntelligenceLayer(envelope, {
      getVerifiedEntries: () => [{
        type: "url_domain",
        value: "malicious.example",
        confirmedThreat: true,
        ruleId: "url-rule-1",
      }],
    });

    expect(result.incomplete).toBe(false);
    expect(result.blocksSafeVerdict).toBeUndefined();
  });
});

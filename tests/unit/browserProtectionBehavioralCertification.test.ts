import { describe, expect, it } from "vitest";
import { evaluateBrowserUrl } from "../../server/src/consumer/browserProtection.js";
import { createDestinationAnalysisCoordinator } from "../../server/src/workflows/analyzeLinks.js";

const EICAR_TEST_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

function coordinator(body: string | null) {
  return createDestinationAnalysisCoordinator({
    networkEnabled: true,
    cacheKey: Buffer.alloc(32, 31),
    fetchImpl: async (url) => body === null ? null : ({
      finalUrl: url,
      contentType: "text/html",
      body,
    }),
  });
}

describe("Browser Protection behavioral certification", () => {
  it("blocks a destination whose actually fetched content matches deterministic malware evidence", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/download",
      context: "explicit_check",
    }, {
      destinationAnalyzer: coordinator(`<html><body><pre>${EICAR_TEST_SIGNATURE}</pre></body></html>`),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("malware");
    expect(result.disposition).toBe("block");
    expect(result.reasonCodes).toContain("DESTINATION_MALWARE");
    expect(result.explanation).toMatch(/do not continue/i);
  });

  it("blocks a credential-collection destination after real destination HTML classification", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/login",
      context: "navigation",
    }, {
      destinationAnalyzer: coordinator("<html><form><input name=user><input type=password></form></html>"),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("credential_trap");
    expect(result.disposition).toBe("block");
    expect(result.reasonCodes).toContain("DESTINATION_CREDENTIAL_TRAP");
  });

  it("warns on a deterministic fake-support destination even when no mailbox context exists", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/support",
      context: "navigation",
    }, {
      destinationAnalyzer: coordinator("<html><body>Your computer is infected. Call now to speak with our support agent.</body></html>"),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("fake_support");
    expect(result.disposition).toBe("warn");
    expect(result.reasonCodes).toContain("DESTINATION_FAKE_SUPPORT");
  });

  it("never allows a destination when bounded acquisition fails", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/ordinary",
      context: "explicit_check",
    }, {
      destinationAnalyzer: coordinator(null),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("error");
    expect(result.disposition).not.toBe("allow");
    expect(result.explanation).toMatch(/not treated as safe|verify/i);
  });

  it("warns on executable download metadata even when the inspected destination itself is benign", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/files",
      context: "download",
      download: { filename: "invoice-viewer.exe", mimeType: "application/octet-stream" },
    }, {
      destinationAnalyzer: coordinator("<html><body>ordinary documentation download page</body></html>"),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("benign");
    expect(result.reasonCodes).toContain("EXECUTABLE_OR_SCRIPT_DOWNLOAD");
    expect(result.disposition).toBe("warn");
  });

  it("warns on macro-capable office downloads rather than silently allowing them", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/files",
      context: "download",
      download: { filename: "invoice.xlsm", mimeType: "application/vnd.ms-excel.sheet.macroEnabled.12" },
    }, {
      destinationAnalyzer: coordinator("<html><body>ordinary documentation download page</body></html>"),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("benign");
    expect(result.reasonCodes).toContain("MACRO_CAPABLE_DOCUMENT_DOWNLOAD");
    expect(result.disposition).toBe("warn");
  });

  it("allows an ordinary explicitly checked destination only when the signed intelligence cache is verified and empty", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/help",
      context: "explicit_check",
    }, {
      destinationAnalyzer: coordinator("<html><body>ordinary public documentation and help information</body></html>"),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(result.destinationClassification).toBe("benign");
    expect(result.disposition).toBe("allow");
    expect(result.explanation).toMatch(/not a guarantee/i);
  });

  it("preserves authoritative HTTP versus HTTPS transport evidence without changing a benign disposition", async () => {
    const body = "<html><body>ordinary public documentation and help information</body></html>";
    const http = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "http://example.com/help",
      context: "explicit_check",
    }, {
      destinationAnalyzer: coordinator(body),
      scamCheck: { intelligenceEntries: [] },
    });
    const https = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/help",
      context: "explicit_check",
    }, {
      destinationAnalyzer: coordinator(body),
      scamCheck: { intelligenceEntries: [] },
    });

    expect(http.destinationClassification).toBe("benign");
    expect(https.destinationClassification).toBe("benign");
    expect(http.disposition).toBe("allow");
    expect(https.disposition).toBe("allow");
    expect(http.explanation).toMatch(/unencrypted HTTP transport/i);
    expect(https.explanation).toMatch(/HTTPS transport/i);
    expect(http.explanation).not.toBe(https.explanation);
  });

  it("fails closed when signed Global Shield intelligence is unavailable even if fetched content looks benign", async () => {
    const result = await evaluateBrowserUrl({
      schemaVersion: 1,
      url: "https://example.com/help",
      context: "explicit_check",
    }, {
      destinationAnalyzer: coordinator("<html><body>ordinary public documentation and help information</body></html>"),
      scamCheck: { intelligenceEntries: null },
    });

    expect(result.destinationClassification).toBe("benign");
    expect(result.disposition).toBe("unknown");
    expect(result.reasonCodes).toContain("GLOBAL_INTELLIGENCE_UNAVAILABLE");
  });
});

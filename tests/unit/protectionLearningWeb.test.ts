import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const webRoot = join(import.meta.dirname, "../../web");
const source = readFileSync(join(webRoot, "protection-learning.js"), "utf8");
const scripts = readFileSync(join(import.meta.dirname, "../../server/src/api/dashboardScripts.ts"), "utf8");

describe("durable protection browser wiring", () => {
  it("loads the protection-learning module from the server-owned script composition", () => {
    expect(scripts).toContain('"/protection-learning.js"');
  });

  it("intercepts Block before the legacy raw-address handler and submits opaque token plus explicit family choice only", () => {
    expect(source).toContain("event.stopImmediatePropagation()");
    expect(source).toContain("`block-${scope}`, { token, shareWithFamily }");
    expect(source).toContain("Cancel keeps the ${scope} block personal");
    expect(source).not.toMatch(/`block-\$\{scope\}`\s*,\s*\{[^}]*address/s);
    expect(source).not.toMatch(/`block-\$\{scope\}`\s*,\s*\{[^}]*domain/s);
    expect(source).not.toMatch(/`block-\$\{scope\}`\s*,\s*\{[^}]*subject/s);
  });

  it("owns Report Scam before the legacy handler and sends only token plus the explicit sender-block choice", () => {
    expect(source).toContain("[data-action=\"report-scam\"]");
    expect(source).toContain("await handleReportScam(button, accountId, token, card)");
    expect(source).toContain("post(accountId, 'report-scam', { token, blockSender })");
    expect(source).not.toContain("post(accountId, 'trash', { token })");
    expect(source).toContain("future matches will auto-Trash");
    expect(source).toContain("Family Shield updated");
  });

  it("reports partial external failures without undoing durable local campaign protection", () => {
    expect(source).toContain("result.localProtected !== true");
    expect(source).toContain("Local protection is still active");
    expect(source).toContain("result.movedCurrent === true");
    expect(source).toContain("result.communityAccepted === true");
    expect(source).toContain("Local protection remains active");
  });

  it("sends positive learning only after Safe or Trust succeeds", () => {
    expect(source).toContain("Message marked Safe ✓");
    expect(source).toContain("Sender trusted ✓");
    expect(source).toContain("post(accountId, 'legitimate-feedback', { token })");
  });

  it("never serializes raw message content or provider message identity into learning calls", () => {
    for (const forbidden of ["textPreview", "htmlSignals", "providerNativeId", "messageId", "rawBody", "bodyText"]) {
      expect(source).not.toContain(forbidden);
    }
  });
});

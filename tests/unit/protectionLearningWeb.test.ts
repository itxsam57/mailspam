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

  it("intercepts Block before the legacy raw-address handler and submits only the opaque scan token", () => {
    expect(source).toContain("event.stopImmediatePropagation()");
    expect(source).toContain("`block-${scope}`, { token }");
    expect(source).not.toMatch(/`block-\$\{scope\}`\s*,\s*\{[^}]*address/s);
    expect(source).not.toMatch(/`block-\$\{scope\}`\s*,\s*\{[^}]*domain/s);
  });

  it("moves a successfully reported scam to Trash only after local report protection succeeds", () => {
    expect(source).toContain("Campaign protected locally ✓");
    expect(source).toContain("if (kind === 'report') void trashReportedMessage(accountId, token, card)");
    expect(source).toContain("post(accountId, 'trash', { token })");
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

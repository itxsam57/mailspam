import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd(), "..");
const source = readFileSync(resolve(root, "web/unsubscribe-monitor.js"), "utf8");

describe("mailto unsubscribe consumer fallback", () => {
  it("never auto-launches the browser or OS mail protocol handler", () => {
    expect(source).not.toContain("anchor.click()");
    expect(source).not.toContain("document.createElement('a')");
  });

  it("keeps mailto completion explicitly manual and copyable inside Email Shield", () => {
    expect(source).toContain("copy-unsubscribe-email");
    expect(source).toContain("navigator.clipboard.writeText");
    expect(source).toContain("Email Shield cannot send this unsubscribe email with the connected mailbox permissions");
    expect(source).toContain("Nothing was opened automatically");
  });

  it("does not record a mailto request as opened before the user actually sends anything", () => {
    expect(source).toContain("if (method === 'link_only')");
    expect(source).toContain("await recordManualActivity(accountId, token, actionKey, method)");
    expect(source).not.toContain("A pre-addressed unsubscribe email was opened");
    expect(source).not.toContain("Manual unsubscribe handoff recorded in Activity");
  });
});

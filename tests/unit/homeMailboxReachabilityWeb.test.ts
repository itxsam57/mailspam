import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("Home mailbox reachability presentation", () => {
  it("carries sanitized account reachability through the existing account-chip owner", () => {
    const source = read("web/index.html");
    expect(source).toContain("row.dataset.reachability");
    expect(source).toContain("account.reachability?.state");
    expect(source).toContain("'checking'");
    expect(source).toContain("'reachable'");
    expect(source).toContain("'unavailable'");
    expect(source).toContain("'unknown'");
  });

  it("renders Home fail-closed instead of treating selection as proof of protection", () => {
    const source = read("web/app-shell.js");
    expect(source).not.toContain("Protection ready for selected mailbox");
    expect(source).toContain("Checking mailbox connection");
    expect(source).toContain("Mailbox connection verified");
    expect(source).toContain("Mailbox connection needs attention");
    expect(source).toContain("Mailbox status unavailable");
    expect(source).toContain("selected?.dataset.reachability");
    expect(source).toContain("homeProtectionIndicator.dataset.reachability");
  });

  it("reserves the green Home indicator for a verified reachable mailbox", () => {
    const source = read("web/app-shell.js");
    expect(source).toContain('.home-protection-state[data-reachability="reachable"]');
    expect(source).toContain('.home-protection-state[data-reachability="unavailable"]');
    expect(source).toContain('.home-protection-state[data-reachability="checking"]');
    expect(source).toContain('.home-protection-state[data-reachability="unknown"]');
    expect(source).not.toContain('.home-protection-state{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--safe)');
  });
});

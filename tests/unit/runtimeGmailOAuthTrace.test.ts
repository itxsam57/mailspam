import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const onboarding = readFileSync(join(root, "web/consumer-provider-onboarding.js"), "utf8");
const serverRoot = join(root, "server/src");

function filesUnder(path: string): string[] {
  const output: string[] = [];
  for (const name of readdirSync(path)) {
    const full = join(path, name);
    if (statSync(full).isDirectory()) output.push(...filesUnder(full));
    else if (/\.(ts|js)$/.test(name)) output.push(full);
  }
  return output;
}

const serverSource = filesUnder(serverRoot).map((path) => readFileSync(path, "utf8")).join("\n");

describe("Gmail OAuth final-testing trace", () => {
  it("keeps authentication/persistence milestones with server owners and visible completion with the consumer UI owner", () => {
    expect(serverSource).toContain("provider_authenticated");
    expect(serverSource).toContain("connection_persisted");
    expect(onboarding).toContain("provider.connect.gmail.ui_confirmed");
    expect(onboarding).not.toContain("provider.connect.gmail.provider_authenticated");
    expect(onboarding).not.toContain("provider.connect.gmail.connection_persisted");
  });
});

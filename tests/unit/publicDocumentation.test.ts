import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("public security and deployment documentation", () => {
  it("states the implemented privacy boundary and user-controlled actions", () => {
    const privacy = read("PRIVACY.md");
    expect(privacy).toContain("does not send message bodies");
    expect(privacy).toContain("2,000 pending reports");
    expect(privacy).toContain("90 days");
    expect(privacy).toContain("Ordinary uninstall preserves user data");
    for (const excluded of ["mailbox address/proof", "subject", "body", "provider message IDs", "credentials"]) expect(privacy).toContain(excluded);
  });

  it("publishes private disclosure, trust boundaries and concrete incident playbooks", () => {
    const security = read("SECURITY.md");
    const threat = read("THREAT_MODEL.md");
    const incident = read("INCIDENT_RESPONSE.md");
    expect(security).toContain("security/advisories/new");
    expect(security).toContain("Do not include real mailbox credentials");
    expect(threat).toContain("Browser → loopback service");
    expect(threat).toContain("Feed tamper/replay/equivocation");
    expect(threat).toContain("Android/iOS full mailbox shells are not implemented");
    expect(incident).toContain("Release signing key or distribution compromise");
    expect(incident).toContain("Community feed signing key compromise");
    expect(incident).toContain("Privacy leak in logs/metrics/report schema");
  });

  it("keeps repository completion separate from external and missing platform work", () => {
    const reconciliation = read("docs/THREE_MILESTONE_FINAL_RECONCILIATION.md");
    expect(reconciliation).toContain("The project must not be described as all three milestones formally closed");
    expect(reconciliation).toContain("Android/iOS mailbox application shells are not implemented");
    for (const gap of ["GAP-001", "GAP-002", "GAP-004", "GAP-005", "GAP-008"]) expect(reconciliation).toContain(gap);
  });
});

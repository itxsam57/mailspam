import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(process.cwd(), "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("AI Engineering Automation Kit installation", () => {
  it("keeps the Section 00 project profile, matrix and regression register", () => {
    const profile = read(".engineering/PROJECT_PROFILE.md");
    const matrix = read(".engineering/TEST_MATRIX.md");
    const regressions = read(".engineering/REGRESSION_REGISTER.md");

    expect(profile).toContain("itxsam57/mailspam");
    expect(profile).toContain("Express `4.19.x`");
    expect(profile).toContain("npm with lockfile v3");
    expect(profile).toContain("Database/migrations/seeds: not applicable");
    expect(matrix).toContain("Start compiled service on an isolated localhost port");
    expect(matrix).toContain("Homepage, accounts API, fixture connection, quick-scan SSE completion");
    expect(matrix).toContain("Final visible browser test — owner only");
    expect(regressions).toContain("PRE-001");
    expect(regressions).toContain("DEP-001");
    expect(regressions).toContain("REG-001");
    expect(regressions).toContain("GAP-001");
    expect(regressions).toContain("Do not delete history to make the register appear green");
  });

  it("exposes one full gate without adding unrelated framework checks", () => {
    const rootPackage = JSON.parse(read("package.json"));
    const serverPackage = JSON.parse(read("server/package.json"));

    expect(rootPackage.scripts.verify).toBe("npm run gate");
    expect(rootPackage.scripts.gate).toContain("run-gate.mjs");
    expect(rootPackage.scripts).toMatchObject({
      preflight: expect.any(String),
      typecheck: expect.any(String),
      "test:unit": expect.any(String),
      "test:integration": expect.any(String),
      "check:web": expect.any(String),
      "smoke:server": expect.any(String),
      "smoke:background": expect.any(String),
      "audit:inventory": expect.any(String),
      "audit:prod": expect.any(String),
    });
    expect(serverPackage.scripts.typecheck).toContain("--noEmit");
    expect(serverPackage.scripts["test:unit"]).toContain("tests/unit");
    expect(serverPackage.scripts["test:integration"]).toContain("tests/integration");
    expect(rootPackage.scripts).not.toHaveProperty("test:database");
    expect(rootPackage.scripts).not.toHaveProperty("test:playwright");
  });

  it("generates truthful reports and an owner-visible handoff even when a gate stage fails", () => {
    const gate = read("scripts/engineering/run-gate.mjs");
    const dependencyAudit = read("scripts/engineering/audit-dependencies.mjs");
    expect(gate).toContain("Continuing to collect independent results");
    expect(gate).toContain("verification-report.json");
    expect(gate).toContain("VERIFICATION_REPORT.md");
    expect(gate).toContain("MANUAL_TEST_HANDOFF.md");
    expect(gate).toContain("dependency-audit.json");
    expect(gate).toContain('id: "PRE-001"');
    expect(gate).toContain("preExistingFindings");
    expect(gate).toContain("formerGateCoverage");
    expect(gate).toContain("Do not begin browser acceptance");
    expect(gate).toContain("process.exit(1)");
    expect(dependencyAudit).toContain("All-dependency counts");
    expect(dependencyAudit).toContain("audit:prod");
  });

  it("invokes npm through its JavaScript CLI without platform-specific shell wrappers", () => {
    const gate = read("scripts/engineering/run-gate.mjs");
    const dependencyAudit = read("scripts/engineering/audit-dependencies.mjs");

    for (const source of [gate, dependencyAudit]) {
      expect(source).toContain("process.env.npm_execpath");
      expect(source).toContain("process.execPath");
      expect(source).toContain("shell: false");
      expect(source).not.toContain("npm.cmd");
    }
    expect(gate).toContain('args: [npmCli, "run", script]');
    expect(dependencyAudit).toContain('[npmCli, "audit", "--json"]');
  });

  it("runs the cross-platform gate and uploads handoff evidence on every CI result", () => {
    const workflow = read(".github/workflows/verify.yml");
    expect(workflow).toContain("ubuntu-latest");
    expect(workflow).toContain("windows-latest");
    expect(workflow).toContain("macos-latest");
    expect(workflow).toContain("npm ci");
    expect(workflow).toContain("npm run gate");
    expect(workflow).toContain("ENGINEERING_AUDIT");
    expect(workflow).toContain("if: always()");
    expect(workflow).toContain("actions/upload-artifact@v4");
    expect(workflow).toContain("artifacts/engineering/");
  });

  it("keeps browser automation limited to source/API smoke and leaves visible/live acceptance to the owner", () => {
    const webCheck = read("scripts/engineering/check-web-assets.mjs");
    const smoke = read("scripts/engineering/smoke-server.mjs");
    const handoff = read(".engineering/MANUAL_TEST_HANDOFF_TEMPLATE.md");

    expect(webCheck).toContain('process.execPath, ["--check"');
    expect(webCheck).toContain("privacy-sensitive field");
    expect(smoke).toContain("/api/dev/test-suite");
    expect(smoke).toContain("event: scan-complete");
    expect(smoke).toContain("falseNegatives.length === 0");
    expect(read("scripts/engineering/run-gate.mjs")).toContain('"background-smoke"');

    expect(handoff).toContain("The owner continues only after");
    expect(handoff).toContain("docs/MILESTONE_2_LIVE_ACCEPTANCE.md");
    expect(handoff).toContain("## Live provider checks");
    expect(handoff).toContain("Microsoft public desktop/mobile registration");
    expect(handoff).toContain("Do not mark these complete from a local fixture or unit test");
    expect(handoff).not.toContain("normal Apple ID password");
    expect(handoff).not.toContain("Playwright");
    expect(handoff).not.toContain("Puppeteer");
  });
});

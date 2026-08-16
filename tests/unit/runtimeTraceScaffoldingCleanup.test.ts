import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");

describe("flight recorder release-head hygiene", () => {
  it("does not ship one-shot implementation workflows", () => {
    const workflows = readdirSync(join(root, ".github/workflows"));
    expect(workflows.filter((name) => name.startsWith("flight-recorder-") && name !== "")).toEqual([]);
  });

  it("does not ship branch-local codemod/reconciliation helpers", () => {
    const engineering = readdirSync(join(root, "scripts/engineering"));
    expect(engineering.filter((name) => /^apply-flight-recorder-|^reconcile-flight-recorder-/.test(name))).toEqual([]);
  });

  it("does not ship temporary flight-recorder trigger/marker files", () => {
    const plans = readdirSync(join(root, "docs/superpowers/plans"));
    expect(plans.filter((name) => name.startsWith(".flight-recorder-") || name.startsWith(".keep-flight-recorder-red"))).toEqual([]);
    expect(existsSync(join(root, "docs/superpowers/plans/.flight-recorder-precleanup-green"))).toBe(false);
  });
});

import { describe, expect, it, vi } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import type { ScanResult } from "../../server/src/engine/pipeline.js";
import {
  collectDurableAutoTrashIds,
  DurableProtectionEnforcementError,
  enforceDurableAutoTrash,
  isDurableAutoTrashResult,
} from "../../server/src/workflows/durableProtection.js";

function result(
  providerNativeId: string,
  verdict: ScanResult["scored"]["verdict"],
  codes: string[],
): ScanResult {
  return {
    envelope: { providerNativeId } as CanonicalEnvelope,
    scored: {
      verdict,
      score: codes.length * 10,
      confirmedByRule: verdict === "confirmed_threat",
      evidence: codes.map((code) => ({
        layer: "test",
        code,
        description: code,
        scoreContribution: code === "GLOBAL_WARNING_MATCH" ? 3 : 10,
        source: code.startsWith("GLOBAL_") ? "signed_feed" as const : "personal_rule" as const,
      })),
      layerResults: [],
    },
    action: verdict === "confirmed_threat" ? "auto_trash_allowed" : "none",
  };
}

describe("durable automatic Trash policy", () => {
  it.each([
    "BLOCKED_SENDER",
    "BLOCKED_DOMAIN",
    "LOCALLY_REPORTED_SCAM_CAMPAIGN",
    "GLOBAL_CONFIRMED_MATCH",
  ])("auto-trashes confirmed messages backed by %s", (code) => {
    expect(isDurableAutoTrashResult(result("native-1", "confirmed_threat", [code]))).toBe(true);
  });

  it("never auto-trashes a community warning or heuristic High Risk verdict", () => {
    expect(isDurableAutoTrashResult(result("warning", "review", ["GLOBAL_WARNING_MATCH"]))).toBe(false);
    expect(isDurableAutoTrashResult(result("high", "high_risk", ["CREDENTIAL_PHISH_INTENT", "DMARC_FAIL"]))).toBe(false);
  });

  it("deduplicates provider IDs and refuses to exceed its collection bound", () => {
    const ids = new Set<string>();
    collectDurableAutoTrashIds([
      result("one", "confirmed_threat", ["BLOCKED_SENDER"]),
      result("one", "confirmed_threat", ["BLOCKED_DOMAIN"]),
      result("two", "confirmed_threat", ["LOCALLY_REPORTED_SCAM_CAMPAIGN"]),
    ], ids, 2);
    expect([...ids]).toEqual(["one", "two"]);
    expect(() => collectDurableAutoTrashIds([
      result("three", "confirmed_threat", ["GLOBAL_CONFIRMED_MATCH"]),
    ], ids, 2)).toThrow(DurableProtectionEnforcementError);
  });

  it("uses bounded provider-neutral batches and never permanently deletes", async () => {
    const calls: string[][] = [];
    const adapter = {
      moveToTrash: vi.fn(async (ids: string[]) => { calls.push([...ids]); }),
    };
    const ids = Array.from({ length: 205 }, (_, index) => `id-${index}`);
    const output = await enforceDurableAutoTrash(adapter, ids, new AbortController().signal);
    expect(output).toEqual({ requested: 205, moved: 205 });
    expect(calls.map((batch) => batch.length)).toEqual([100, 100, 5]);
  });

  it("reports truthful partial enforcement when a later provider batch fails", async () => {
    let call = 0;
    const adapter = {
      moveToTrash: vi.fn(async () => {
        call += 1;
        if (call === 2) throw new Error("provider rejected batch");
      }),
    };
    const ids = Array.from({ length: 150 }, (_, index) => `id-${index}`);
    await expect(enforceDurableAutoTrash(adapter, ids, new AbortController().signal)).rejects.toMatchObject({
      name: "DurableProtectionEnforcementError",
      requested: 150,
      moved: 100,
    });
  });
});

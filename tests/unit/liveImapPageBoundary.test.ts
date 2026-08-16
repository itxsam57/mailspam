import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveScanBatchPolicy } from "../../server/src/workers/scanBatchPolicy.js";

describe("authoritative scan execution batch policy", () => {
  it.each(["icloud", "yahoo", "imap"] as const)(
    "caps %s to two-message provider pages even when an upstream route asks for 20",
    (provider) => {
      expect(resolveScanBatchPolicy(provider, "full", 20)).toEqual({
        pageSize: 2,
        maxMessages: undefined,
      });
    },
  );

  it("keeps iCloud Quick Scan at ten total messages while reading only two per provider page", () => {
    expect(resolveScanBatchPolicy("icloud", "quick", 20)).toEqual({
      pageSize: 2,
      maxMessages: 10,
    });
    expect(resolveScanBatchPolicy("icloud", "quick", 2, 100)).toEqual({
      pageSize: 2,
      maxMessages: 10,
    });
  });

  it("does not reduce the normal Gmail execution batch", () => {
    expect(resolveScanBatchPolicy("gmail", "quick", 20)).toEqual({
      pageSize: 20,
      maxMessages: 20,
    });
  });

  it("is enforced by the scan Worker rather than trusted to whichever HTTP route started the scan", () => {
    const worker = readFileSync(join(process.cwd(), "src/workers/scanWorker.ts"), "utf8");
    expect(worker).toContain("resolveScanBatchPolicy(");
    expect(worker).toContain("const { pageSize, maxMessages } = scanBatchPolicy");
    expect(worker).toContain("bounded batches of ${scanBatchPolicy.pageSize}");
    expect(worker).not.toContain("const pageSize = data.pageSize ?? 20");
  });
});

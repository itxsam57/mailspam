import { describe, expect, it, vi } from "vitest";
import { fetchBoundedReadableBodies } from "../../server/src/adapters/imap/imapAdapter.js";
import { inspectBodyStructure } from "../../server/src/adapters/imap/mimeParts.js";

type BodyRequest = { key: string; start: number; maxLength: number };

function selection(parts: Array<{ part: string; type: "text/plain" | "text/html"; size: number | null }>) {
  return inspectBodyStructure({
    type: "multipart/alternative",
    childNodes: parts.map((part) => ({
      part: part.part,
      type: part.type,
      ...(part.size === null ? {} : { size: part.size }),
      encoding: "7bit",
      parameters: { charset: "utf-8" },
    })),
  });
}

function boundedClient(sources: Record<string, Buffer>, override?: (request: BodyRequest, source: Buffer) => Buffer) {
  return {
    fetchOne: vi.fn(async (_range: string | number, query: Record<string, unknown>, _options?: Record<string, unknown>) => {
      expect(query).not.toHaveProperty("source");
      expect(query).not.toHaveProperty("headers");
      const requests = query.bodyParts as BodyRequest[];
      const bodyParts = new Map<string, Buffer>();
      for (const request of requests) {
        const source = sources[request.key]!;
        const defaultResponse = source.subarray(request.start, request.start + request.maxLength);
        bodyParts.set(request.key, override ? override(request, source) : defaultResponse);
      }
      return { bodyParts };
    }),
  };
}

describe("IMAP readable-body completeness", () => {
  it("proves a declared 60 KiB plain-text part complete instead of silently keeping the old 48 KiB prefix", async () => {
    const raw = Buffer.from("A".repeat(60 * 1024), "utf8");
    const selected = selection([{ part: "1", type: "text/plain", size: raw.length }]);
    const client = boundedClient({ "1": raw });

    const result = await fetchBoundedReadableBodies(client, 11, selected, new AbortController().signal);
    const query = client.fetchOne.mock.calls[0]![1] as { bodyParts: BodyRequest[] };

    expect(query.bodyParts[0]!.maxLength).toBeGreaterThan(raw.length);
    expect(result.plain).toHaveLength(raw.length);
    expect(result.truncated).toBe(false);
    expect(result.notes).toEqual([]);
  });

  it("proves a declared 180 KiB HTML alternative complete within the approved readable-part budget", async () => {
    const raw = Buffer.from(`<p>${"B".repeat(180 * 1024 - 7)}</p>`, "utf8");
    const selected = selection([{ part: "2", type: "text/html", size: raw.length }]);
    const client = boundedClient({ "2": raw });

    const result = await fetchBoundedReadableBodies(client, 12, selected, new AbortController().signal);
    const query = client.fetchOne.mock.calls[0]![1] as { bodyParts: BodyRequest[] };

    expect(query.bodyParts[0]!.maxLength).toBeGreaterThan(raw.length);
    expect(result.html?.length).toBeGreaterThan(170 * 1024);
    expect(result.truncated).toBe(false);
  });

  it("keeps a declared 400 KiB readable part bounded and explicitly partial", async () => {
    const raw = Buffer.from("C".repeat(400 * 1024), "utf8");
    const selected = selection([{ part: "1", type: "text/plain", size: raw.length }]);
    const client = boundedClient({ "1": raw });

    const result = await fetchBoundedReadableBodies(client, 13, selected, new AbortController().signal);
    const query = client.fetchOne.mock.calls[0]![1] as { bodyParts: BodyRequest[] };

    expect(query.bodyParts[0]!.maxLength).toBeLessThan(raw.length);
    expect(result.plain!.length).toBeLessThan(raw.length);
    expect(result.truncated).toBe(true);
  });

  it("never calls a declared part complete when the provider returns fewer bytes than BODYSTRUCTURE declared", async () => {
    const raw = Buffer.from("D".repeat(60 * 1024), "utf8");
    const selected = selection([{ part: "1", type: "text/plain", size: raw.length }]);
    const client = boundedClient({ "1": raw }, (_request, source) => source.subarray(0, 50 * 1024));

    const result = await fetchBoundedReadableBodies(client, 14, selected, new AbortController().signal);

    expect(result.truncated).toBe(true);
    expect(result.plain!.length).toBeLessThan(raw.length);
  });

  it("keeps unknown-size readable parts bounded rather than pretending completeness", async () => {
    const raw = Buffer.from("E".repeat(300 * 1024), "utf8");
    const selected = selection([{ part: "1", type: "text/plain", size: null }]);
    const client = boundedClient({ "1": raw });

    const result = await fetchBoundedReadableBodies(client, 15, selected, new AbortController().signal);
    const query = client.fetchOne.mock.calls[0]![1] as { bodyParts: BodyRequest[] };

    expect(query.bodyParts[0]!.maxLength).toBeLessThan(raw.length);
    expect(result.truncated).toBe(true);
  });
});

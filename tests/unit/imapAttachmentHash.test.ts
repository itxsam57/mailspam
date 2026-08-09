import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  fetchBoundedAttachmentHashes,
} from "../../server/src/adapters/imap/imapAdapter.js";
import { inspectBodyStructure } from "../../server/src/adapters/imap/mimeParts.js";
import {
  MAX_ATTACHMENT_HASH_BYTES,
  MAX_ATTACHMENT_HASHES_PER_MESSAGE,
} from "../../server/src/util/attachmentHash.js";

function sha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function requestedBodyParts(query: Record<string, unknown>): Array<{ key: string }> {
  const value = query.bodyParts;
  if (!Array.isArray(value)) throw new Error("Expected bodyParts array in test fetch query.");
  return value as Array<{ key: string }>;
}

describe("bounded IMAP attachment hash acquisition", () => {
  it("fetches only the selected attachment MIME part and hashes the complete decoded bytes", async () => {
    const content = Buffer.from("small attachment bytes", "utf8");
    const encoded = Buffer.from(content.toString("base64"), "ascii");
    const selection = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [
        { part: "1", type: "text/plain", size: 40 },
        {
          part: "2",
          type: "application/pdf",
          size: content.length,
          encoding: "base64",
          disposition: "attachment",
          dispositionParameters: { filename: "invoice.pdf" },
        },
      ],
    });
    const client = {
      fetchOne: vi.fn(async (
        _uid: string | number,
        query: Record<string, unknown>,
        _options?: Record<string, unknown>,
      ) => {
        const parts = requestedBodyParts(query);
        return { bodyParts: new Map<string, Buffer>([[parts[0]!.key, encoded]]) };
      }),
    };

    const result = await fetchBoundedAttachmentHashes(
      client,
      41,
      selection,
      [],
      new AbortController().signal,
    );

    expect(client.fetchOne).toHaveBeenCalledTimes(1);
    expect(client.fetchOne.mock.calls[0]?.[1]).toMatchObject({
      bodyParts: [expect.objectContaining({ key: "2", start: 0 })],
    });
    expect(result.hashesByAttachmentIndex.get(0)).toBe(sha256(content));
    expect(result.incompleteReasons).toEqual([]);
  });

  it("rejects a short provider response instead of hashing an attachment prefix", async () => {
    const prefix = Buffer.from("partial", "utf8");
    const encodedPrefix = Buffer.from(prefix.toString("base64"), "ascii");
    const selection = inspectBodyStructure({
      part: "2",
      type: "application/octet-stream",
      size: 64,
      encoding: "base64",
      disposition: "attachment",
      dispositionParameters: { filename: "truncated.bin" },
    });
    const client = {
      fetchOne: vi.fn(async (
        _uid: string | number,
        query: Record<string, unknown>,
        _options?: Record<string, unknown>,
      ) => {
        const parts = requestedBodyParts(query);
        return { bodyParts: new Map<string, Buffer>([[parts[0]!.key, encodedPrefix]]) };
      }),
    };

    const result = await fetchBoundedAttachmentHashes(
      client,
      45,
      selection,
      [],
      new AbortController().signal,
    );

    expect(client.fetchOne).toHaveBeenCalledTimes(1);
    expect(result.hashesByAttachmentIndex.size).toBe(0);
    expect(result.incompleteReasons.join(" ")).toContain("could not be decoded completely");
    expect([...result.hashesByAttachmentIndex.values()]).not.toContain(sha256(prefix));
  });

  it("does not fetch an attachment whose declared size exceeds the local hash bound", async () => {
    const selection = inspectBodyStructure({
      part: "1",
      type: "application/octet-stream",
      size: MAX_ATTACHMENT_HASH_BYTES + 1,
      disposition: "attachment",
      dispositionParameters: { filename: "large.bin" },
    });
    const client = {
      fetchOne: vi.fn(async (
        _uid: string | number,
        _query: Record<string, unknown>,
        _options?: Record<string, unknown>,
      ) => ({ bodyParts: new Map<string, Buffer>() })),
    };

    const result = await fetchBoundedAttachmentHashes(
      client,
      42,
      selection,
      [],
      new AbortController().signal,
    );

    expect(client.fetchOne).not.toHaveBeenCalled();
    expect(result.hashesByAttachmentIndex.size).toBe(0);
    expect(result.incompleteReasons.join(" ")).toContain("exceeded");
  });

  it("limits exact-hash acquisition to a small fixed attachment count", async () => {
    const childNodes = Array.from({ length: MAX_ATTACHMENT_HASHES_PER_MESSAGE + 2 }, (_, index) => ({
      part: String(index + 1),
      type: "application/octet-stream",
      size: 8,
      encoding: "base64",
      disposition: "attachment",
      dispositionParameters: { filename: `file-${index}.bin` },
    }));
    const selection = inspectBodyStructure({ type: "multipart/mixed", childNodes });
    const client = {
      fetchOne: vi.fn(async (
        _uid: string | number,
        query: Record<string, unknown>,
        _options?: Record<string, unknown>,
      ) => {
        const parts = requestedBodyParts(query);
        return {
          bodyParts: new Map<string, Buffer>(
            parts.map((part) => [part.key, Buffer.from(Buffer.from("12345678").toString("base64"))]),
          ),
        };
      }),
    };

    const result = await fetchBoundedAttachmentHashes(
      client,
      43,
      selection,
      [],
      new AbortController().signal,
    );

    const query = client.fetchOne.mock.calls[0]?.[1];
    const requestedParts = query ? requestedBodyParts(query) : [];
    expect(requestedParts).toHaveLength(MAX_ATTACHMENT_HASHES_PER_MESSAGE);
    expect(result.hashesByAttachmentIndex.size).toBe(MAX_ATTACHMENT_HASHES_PER_MESSAGE);
    expect(result.incompleteReasons.join(" ")).toContain("first");
  });

  it("treats a named inline image as a canonical hashable attachment and reuses its already-fetched QR bytes", async () => {
    const content = Buffer.from("not-a-real-png-but-already-decoded-fixture", "utf8");
    const selection = inspectBodyStructure({
      part: "2",
      type: "image/png",
      size: content.length,
      disposition: "inline",
      dispositionParameters: { filename: "code.png" },
    });
    const client = {
      fetchOne: vi.fn(async (
        _uid: string | number,
        _query: Record<string, unknown>,
        _options?: Record<string, unknown>,
      ) => ({ bodyParts: new Map<string, Buffer>() })),
    };

    expect(selection.attachments).toHaveLength(1);
    expect(selection.hashableAttachments).toEqual([
      expect.objectContaining({ part: "2", attachmentIndex: 0, name: "code.png", mimeType: "image/png" }),
    ]);

    const result = await fetchBoundedAttachmentHashes(
      client,
      44,
      selection,
      [{ part: "2", name: "code.png", mimeType: "image/png", content }],
      new AbortController().signal,
    );

    expect(client.fetchOne).not.toHaveBeenCalled();
    expect(result.hashesByAttachmentIndex.get(0)).toBe(sha256(content));
    expect(result.incompleteReasons).toEqual([]);
  });
});

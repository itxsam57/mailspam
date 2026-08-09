import { describe, expect, it, vi } from "vitest";
import {
  createHardenedFetch,
  isPublicAnalyzeAddress,
  MAX_ANALYZE_BODY_BYTES,
  type ResolvedAddress,
} from "../../server/src/util/hardenedFetch.js";
import { classifyDestination } from "../../server/src/engine/layers/destinationClassification.js";

async function* chunks(...values: Array<string | Buffer>): AsyncGenerator<Uint8Array> {
  for (const value of values) yield Buffer.isBuffer(value) ? value : Buffer.from(value);
}

function response(
  statusCode: number,
  headers: Record<string, string>,
  bodyValues: Array<string | Buffer> = [],
) {
  const cancel = vi.fn();
  return {
    statusCode,
    headers,
    body: chunks(...bodyValues),
    cancel,
  };
}

const PUBLIC_V4: ResolvedAddress = { address: "93.184.216.34", family: 4 };
const PUBLIC_V6: ResolvedAddress = { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 };

describe("Analyze Links DNS-pinned fetch", () => {
  it("pins the request to the validated DNS answer without a second resolution", async () => {
    const resolveHost = vi.fn(async () => [PUBLIC_V4, PUBLIC_V6]);
    const requestPinned = vi.fn(async (_target: URL, pinned: ResolvedAddress) =>
      response(200, { "content-type": "text/html" }, ["<html><form><input type=password></form></html>"]),
    );
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    const result = await fetcher("https://login.example.test/account?q=1");

    expect(result?.finalUrl).toBe("https://login.example.test/account?q=1");
    expect(resolveHost).toHaveBeenCalledTimes(1);
    expect(resolveHost).toHaveBeenCalledWith("login.example.test");
    expect(requestPinned).toHaveBeenCalledTimes(1);
    expect(requestPinned.mock.calls[0]?.[1]).toEqual(PUBLIC_V4);
    expect(requestPinned.mock.calls[0]?.[0].hostname).toBe("login.example.test");
  });

  it("rejects a mixed public/private DNS answer before any network request", async () => {
    const resolveHost = vi.fn(async () => [
      PUBLIC_V4,
      { address: "127.0.0.1", family: 4 as const },
    ]);
    const requestPinned = vi.fn();
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    await expect(fetcher("https://mixed.example.test/")).resolves.toBeNull();
    expect(requestPinned).not.toHaveBeenCalled();
  });

  it("re-resolves and re-validates every redirect hop and blocks a private redirect target", async () => {
    const resolveHost = vi.fn(async (hostname: string) => {
      if (hostname === "first.example.test") return [PUBLIC_V4];
      return [{ address: "169.254.169.254", family: 4 as const }];
    });
    const requestPinned = vi.fn(async () =>
      response(302, { location: "http://metadata.example.test/latest/meta-data/" }),
    );
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    await expect(fetcher("https://first.example.test/start")).resolves.toBeNull();
    expect(resolveHost).toHaveBeenNthCalledWith(1, "first.example.test");
    expect(resolveHost).toHaveBeenNthCalledWith(2, "metadata.example.test");
    expect(requestPinned).toHaveBeenCalledTimes(1);
  });

  it("blocks non-public IPv4 and IPv6 representations, including IPv4-mapped IPv6", () => {
    const blocked = [
      "0.0.0.0",
      "10.1.2.3",
      "100.64.0.1",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "192.168.1.1",
      "198.18.0.1",
      "224.0.0.1",
      "::1",
      "::ffff:127.0.0.1",
      "64:ff9b::c0a8:101",
      "2001:db8::1",
      "2002:7f00:1::",
      "fc00::1",
      "fe80::1",
      "ff02::1",
    ];
    for (const address of blocked) expect(isPublicAnalyzeAddress(address), address).toBe(false);
    expect(isPublicAnalyzeAddress(PUBLIC_V4.address)).toBe(true);
    expect(isPublicAnalyzeAddress(PUBLIC_V6.address)).toBe(true);
  });

  it("rejects URL credentials and non-http schemes before DNS", async () => {
    const resolveHost = vi.fn(async () => [PUBLIC_V4]);
    const requestPinned = vi.fn();
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    await expect(fetcher("https://user:pass@example.test/login")).resolves.toBeNull();
    await expect(fetcher("file:///etc/passwd")).resolves.toBeNull();
    expect(resolveHost).not.toHaveBeenCalled();
    expect(requestPinned).not.toHaveBeenCalled();
  });

  it("fails closed when declared or streamed body size exceeds the cap", async () => {
    const resolveHost = vi.fn(async () => [PUBLIC_V4]);
    const declared = response(200, {
      "content-type": "text/html",
      "content-length": String(MAX_ANALYZE_BODY_BYTES + 1),
    }, ["small"]);
    const streamed = response(200, { "content-type": "text/html" }, [
      Buffer.alloc(MAX_ANALYZE_BODY_BYTES),
      Buffer.from("x"),
    ]);
    const requestPinned = vi
      .fn()
      .mockResolvedValueOnce(declared)
      .mockResolvedValueOnce(streamed);
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    await expect(fetcher("https://large.example.test/declared")).resolves.toBeNull();
    await expect(fetcher("https://large.example.test/streamed")).resolves.toBeNull();
    expect(declared.cancel).toHaveBeenCalled();
    expect(streamed.cancel).toHaveBeenCalled();
  });

  it("rejects compressed text instead of classifying unread bytes as clean", async () => {
    const resolveHost = vi.fn(async () => [PUBLIC_V4]);
    const compressed = response(200, {
      "content-type": "text/html",
      "content-encoding": "gzip",
    }, ["not-decoded"]);
    const requestPinned = vi.fn(async () => compressed);
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    await expect(fetcher("https://compressed.example.test/")).resolves.toBeNull();
    expect(compressed.cancel).toHaveBeenCalled();
  });

  it("does not read unsupported content and the classifier refuses to call it benign", async () => {
    const resolveHost = vi.fn(async () => [PUBLIC_V4]);
    const binary = response(200, { "content-type": "application/octet-stream" }, ["MZ-binary"]);
    const requestPinned = vi.fn(async () => binary);
    const fetcher = createHardenedFetch({ resolveHost, requestPinned });

    const fetched = await fetcher("https://download.example.test/file.exe");
    expect(fetched).toEqual({
      finalUrl: "https://download.example.test/file.exe",
      contentType: "application/octet-stream",
      body: "",
    });
    expect(binary.cancel).toHaveBeenCalled();

    const classified = await classifyDestination("https://download.example.test/file.exe", async () => fetched);
    expect(classified.classification).toBe("error");
    expect(classified.detail).toContain("not treated as benign");
  });

  it("enforces the redirect cap without fetching a fourth redirect target", async () => {
    const resolveHost = vi.fn(async () => [PUBLIC_V4]);
    let redirectNumber = 0;
    const requestPinned = vi.fn(async () => {
      redirectNumber += 1;
      return response(302, { location: `https://r${redirectNumber}.example.test/` });
    });
    const fetcher = createHardenedFetch({ resolveHost, requestPinned, maxRedirects: 3 });

    await expect(fetcher("https://r0.example.test/")).resolves.toBeNull();
    expect(requestPinned).toHaveBeenCalledTimes(4);
    expect(resolveHost).toHaveBeenCalledTimes(4);
  });
});

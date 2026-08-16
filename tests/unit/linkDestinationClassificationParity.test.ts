import { describe, expect, it, vi } from "vitest";
import { classifyDestination } from "../../server/src/engine/layers/destinationClassification.js";
import { analyzeHtmlInteractions, canonicalizeWebDestination } from "../../server/src/util/htmlInteraction.js";

describe("encoded destination classification parity", () => {
  it("feeds one canonical public HTTPS destination to the existing classifier", async () => {
    const raw = "https%3A%2F%2Fshop.example%2Faccount";
    const link = analyzeHtmlInteractions(`<a href="${raw}">Account</a>`, null).links[0];
    expect(link?.rawUrl).toBe(raw);
    expect(link?.normalizedUrl).toBe("https://shop.example/account");

    const fetchImpl = vi.fn(async (url: string) => ({
      finalUrl: url,
      contentType: "text/html",
      body: "<html><body>Ordinary storefront content.</body></html>",
    }));
    const result = await classifyDestination(link!.normalizedUrl, fetchImpl);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledWith("https://shop.example/account");
    expect(result.classification).toBe("benign");
  });

  it("keeps encoded loopback under the existing blocked-target policy without fetching", async () => {
    const canonical = canonicalizeWebDestination("http%3A%2F%2F127.0.0.1%2Fadmin", null);
    const fetchImpl = vi.fn();
    const result = await classifyDestination(canonical, fetchImpl);

    expect(canonical).toBe("http://127.0.0.1/admin");
    expect(result.classification).toBe("blocked_unsafe_target");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    "https%253A%252F%252Fshop.example%252Faccount",
    "https%3A%2F%2Fuser%3Asecret%40shop.example%2F",
    "javascript%3Aalert%281%29",
  ])("never fetches an encoded destination that did not become a validated web URL: %s", async (raw) => {
    const canonical = canonicalizeWebDestination(raw, null);
    const fetchImpl = vi.fn();
    const result = await classifyDestination(canonical, fetchImpl);

    expect(canonical).toBe(raw);
    expect(result.classification).toBe("error");
    expect(result.detail).toBe("Malformed URL.");
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

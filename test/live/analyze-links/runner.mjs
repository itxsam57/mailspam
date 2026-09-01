import assert from "node:assert/strict";
import { lookup as dnsLookup } from "node:dns/promises";
import {
  createHardenedFetch,
  hardenedFetch,
} from "../../../server/dist/util/hardenedFetch.js";
import { classifyDestination } from "../../../server/dist/engine/layers/destinationClassification.js";

const publicBase = process.argv[2];
const compressedPublicBase = process.argv[3] || publicBase;
assert(publicBase, "public target base URL is required");
const base = new URL(publicBase);
const compressedBase = new URL(compressedPublicBase);
assert.equal(base.protocol, "https:", "controlled target must be public HTTPS");
assert.equal(compressedBase.protocol, "https:", "controlled compressed target must be public HTTPS");

const results = [];
function pass(id, detail) {
  results.push({ id, status: "PASS", detail });
  console.log(`${id} PASS — ${detail}`);
}

// LIVE-G01: direct controlled public HTTPS target goes through the shipping fetcher.
{
  const url = new URL("/direct", base).toString();
  const result = await classifyDestination(url, hardenedFetch);
  assert.equal(result.classification, "credential_trap");
  assert.equal(result.hasPasswordField, true);
  pass("LIVE-G01", "direct public HTTPS target fetched and credential-form content classified through production hardenedFetch");
}

// LIVE-G02: redirect hop re-resolves and then uses the shipping pinned request.
{
  let resolutionCount = 0;
  const liveCountingResolver = async (hostname) => {
    resolutionCount += 1;
    const records = await dnsLookup(hostname, { all: true, verbatim: true });
    return records.map((record) => ({ address: record.address, family: record.family === 6 ? 6 : 4 }));
  };
  const instrumentedProductionFetch = createHardenedFetch({ resolveHost: liveCountingResolver });
  const url = new URL("/redirect-public", base).toString();
  const result = await classifyDestination(url, instrumentedProductionFetch);
  assert.equal(result.classification, "credential_trap");
  assert.ok(resolutionCount >= 2, `expected a fresh DNS resolution for redirect hop, observed ${resolutionCount}`);
  pass("LIVE-G02", `public redirect re-resolved before the next pinned request (${resolutionCount} live resolutions)`);
}

// LIVE-G03: a public response cannot redirect the analyzer into loopback/private space.
{
  const url = new URL("/redirect-private", base).toString();
  const result = await classifyDestination(url, hardenedFetch);
  assert.equal(result.classification, "error");
  assert.match(result.detail, /blocked by network safety checks|Fetch failed/i);
  pass("LIVE-G03", "public redirect to loopback was rejected by the production transport");
}

// LIVE-G04: real DNS returns a mixed public/private A-record set and the shipping
// validation layer rejects it before any socket request is allowed to begin.
{
  const mixedHost = "make-1-1-1-1-and-127-0-0-1-rr.1u.ms";
  const records = await dnsLookup(mixedHost, { all: true, verbatim: true });
  const addresses = records.map((record) => record.address);
  assert.ok(addresses.includes("1.1.1.1"), `live mixed DNS response missing public address: ${addresses.join(", ")}`);
  assert.ok(addresses.includes("127.0.0.1"), `live mixed DNS response missing private address: ${addresses.join(", ")}`);

  let requestAttempted = false;
  const observableBoundaryFetch = createHardenedFetch({
    requestPinned: async () => {
      requestAttempted = true;
      throw new Error("requestPinned must not be reached for a mixed DNS answer set");
    },
  });
  const fetched = await observableBoundaryFetch(`http://${mixedHost}/`);
  assert.equal(fetched, null);
  assert.equal(requestAttempted, false, "mixed DNS answer set reached the socket boundary");
  pass("LIVE-G04", `mixed live DNS answer set (${addresses.join(", ")}) rejected before socket creation`);
}

// LIVE-G05: unsupported, oversized and compressed responses never become benign.
// The compressed subcase may use a second controlled HTTPS tunnel because some
// reverse proxies transparently decode origin gzip despite the client requesting
// identity, which would mean the production transport never actually receives
// compressed content to reject.
{
  for (const path of ["/unsupported", "/oversize"]) {
    const result = await classifyDestination(new URL(path, base).toString(), hardenedFetch);
    assert.equal(result.classification, "error", `${path} was incorrectly classified as ${result.classification}`);
  }
  const compressedResult = await classifyDestination(new URL("/compressed", compressedBase).toString(), hardenedFetch);
  assert.equal(compressedResult.classification, "error", `/compressed was incorrectly classified as ${compressedResult.classification}`);
  pass("LIVE-G05", "unsupported, oversized and compressed controlled responses all remained error/uninspectable");
}

// LIVE-G06: observe the headers that actually arrive at the controlled public target.
{
  const fetched = await hardenedFetch(new URL("/headers", base).toString());
  assert.ok(fetched, "header evidence endpoint was not fetched");
  const evidence = JSON.parse(fetched.body);
  assert.equal(evidence.authorizationPresent, false);
  assert.equal(evidence.cookiePresent, false);
  assert.equal(evidence.userAgent, "EmailShieldLinkAnalyzer/1.0");
  assert.equal(evidence.acceptEncoding, "identity");
  assert.equal(evidence.method, "GET");
  pass("LIVE-G06", "no Authorization or Cookie reached the public target; dedicated UA, identity encoding and GET were observed");
}

assert.equal(results.length, 6);
console.log("ANALYZE_LINKS_LIVE_ACCEPTANCE=PASS");
console.log(JSON.stringify({ publicBase: base.origin, compressedPublicBase: compressedBase.origin, results }, null, 2));

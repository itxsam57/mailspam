import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import {
  PERSONAL_POLICY_EXPORT_SCHEMA,
  PERSONAL_POLICY_EXPORT_VERSION,
  PERSONAL_POLICY_RESET_CONFIRMATION,
} from "../../server/src/api/policyManagement.js";

interface BrowserContext {
  baseUrl: string;
  cookie: string;
  csrf: string;
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function start(): Promise<BrowserContext> {
  const app = createLocalDesktopServer({ security: new LocalSecurityManager(), developmentEntitlementsEnabled: true });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  return {
    baseUrl,
    cookie: home.headers.get("set-cookie")?.split(";", 1)[0] ?? "",
    csrf: html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "",
  };
}

function protectedHeaders(context: BrowserContext, extra: Record<string, string> = {}) {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...extra,
  };
}

async function nonce(context: BrowserContext): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(context),
  });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function mutate(
  context: BrowserContext,
  path: string,
  body: unknown,
  method = "POST",
): Promise<Response> {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: method === "DELETE" ? undefined : JSON.stringify(body),
  });
}

function policyDocument(overrides: Partial<Record<string, string[]>> = {}) {
  return {
    schema: PERSONAL_POLICY_EXPORT_SCHEMA,
    version: PERSONAL_POLICY_EXPORT_VERSION,
    policy: {
      blockedSenders: overrides.blockedSenders ?? ["blocked@policy.example"],
      blockedDomains: overrides.blockedDomains ?? ["blocked-domain.example"],
      catchTrashSenders: overrides.catchTrashSenders ?? ["catch@policy.example"],
      catchTrashDomains: overrides.catchTrashDomains ?? ["catch-domain.example"],
      trustedSenders: overrides.trustedSenders ?? ["trusted@policy.example"],
      approvedExceptions: overrides.approvedExceptions ?? [`message:${"a".repeat(64)}`],
      unsubscribedActions: overrides.unsubscribedActions ?? ["b".repeat(64)],
      reportedCampaigns: overrides.reportedCampaigns ?? ["c".repeat(64)],
    },
  };
}

function legacyPolicyDocument() {
  const extended = policyDocument();
  const { catchTrashSenders: _senders, catchTrashDomains: _domains, ...legacyPolicy } = extended.policy;
  return { ...extended, policy: legacyPolicy };
}

async function readPolicy(context: BrowserContext, accountId: string) {
  const response = await fetch(`${context.baseUrl}/api/accounts/${accountId}/personal-policy`, {
    headers: protectedHeaders(context),
  });
  expect(response.status).toBe(200);
  return response.json();
}

describe("protected personal policy management centre API", () => {
  it("supports strict import/export, Catch & Trash backup, bulk revoke, category clear and confirmed reset without exporting secrets", async () => {
    const context = await start();
    const connected = await mutate(context, "/api/accounts/connect", {
      provider: "gmail",
      mode: "fixture",
      label: "policy-management-test",
    });
    expect(connected.status).toBe(200);
    const accountId = (await connected.json()).accountId as string;

    const unauthenticatedExport = await fetch(`${context.baseUrl}/api/accounts/${accountId}/personal-policy/export`);
    expect(unauthenticatedExport.status).toBe(401);

    const replace = await mutate(context, `/api/accounts/${accountId}/personal-policy/import`, {
      mode: "replace",
      document: policyDocument(),
    });
    expect(replace.status).toBe(200);
    expect(await replace.json()).toMatchObject({
      success: true,
      mode: "replace",
      counts: {
        blockedSenders: 1,
        blockedDomains: 1,
        catchTrashSenders: 1,
        catchTrashDomains: 1,
        trustedSenders: 1,
        approvedExceptions: 1,
        unsubscribedActions: 1,
        reportedCampaigns: 1,
      },
    });

    let policy = await readPolicy(context, accountId);
    expect(policy.blockedSenders).toEqual(["blocked@policy.example"]);
    expect(policy.blockedDomains).toEqual(["blocked-domain.example"]);
    expect(policy.catchTrashSenders).toEqual(["catch@policy.example"]);
    expect(policy.catchTrashDomains).toEqual(["catch-domain.example"]);
    expect(policy.trustedSenders).toEqual(["trusted@policy.example"]);
    expect(policy.approvedExceptions).toEqual([`message:${"a".repeat(64)}`]);
    expect(policy.unsubscribedActions).toEqual(["b".repeat(64)]);
    expect(policy.reportedCampaigns).toEqual(["c".repeat(64)]);

    const exported = await fetch(`${context.baseUrl}/api/accounts/${accountId}/personal-policy/export`, {
      headers: protectedHeaders(context),
    });
    expect(exported.status).toBe(200);
    expect(exported.headers.get("cache-control")).toContain("no-store");
    expect(exported.headers.get("content-disposition")).toContain("email-shield-personal-policy.json");
    const exportText = await exported.text();
    const exportBody = JSON.parse(exportText);
    expect(exportBody).toEqual(policyDocument());
    for (const forbidden of [
      "accountId",
      "accountKey",
      "credentials",
      "refreshToken",
      "accessToken",
      "idToken",
      "appPassword",
      "clientSecret",
      "codeVerifier",
    ]) {
      expect(exportText).not.toContain(forbidden);
    }

    const rejected = await mutate(context, `/api/accounts/${accountId}/personal-policy/import`, {
      mode: "replace",
      document: { ...policyDocument(), refreshToken: "must-never-be-accepted" },
    });
    expect(rejected.status).toBe(400);
    policy = await readPolicy(context, accountId);
    expect(policy.blockedSenders).toEqual(["blocked@policy.example"]);

    const merge = await mutate(context, `/api/accounts/${accountId}/personal-policy/import`, {
      mode: "merge",
      document: policyDocument({
        blockedSenders: ["second@policy.example"],
        blockedDomains: [],
        catchTrashSenders: ["second-catch@policy.example"],
        catchTrashDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
        reportedCampaigns: ["d".repeat(64)],
      }),
    });
    expect(merge.status).toBe(200);
    policy = await readPolicy(context, accountId);
    expect(policy.blockedSenders).toEqual(["blocked@policy.example", "second@policy.example"]);
    expect(policy.catchTrashSenders).toEqual(["catch@policy.example", "second-catch@policy.example"]);
    expect(policy.reportedCampaigns).toEqual(["c".repeat(64), "d".repeat(64)]);

    const bulk = await mutate(context, `/api/accounts/${accountId}/personal-policy/bulk-revoke`, {
      items: [
        { category: "blockedSenders", value: "blocked@policy.example" },
        { category: "catchTrashSenders", value: "catch@policy.example" },
        { category: "reportedCampaigns", value: "d".repeat(64) },
        { category: "reportedCampaigns", value: "d".repeat(64) },
      ],
    });
    expect(bulk.status).toBe(200);
    expect((await bulk.json()).revoked).toBe(3);
    policy = await readPolicy(context, accountId);
    expect(policy.blockedSenders).toEqual(["second@policy.example"]);
    expect(policy.catchTrashSenders).toEqual(["second-catch@policy.example"]);
    expect(policy.reportedCampaigns).toEqual(["c".repeat(64)]);

    const clearTrusted = await mutate(context, `/api/accounts/${accountId}/personal-policy/clear-category`, {
      category: "trustedSenders",
      confirmation: "trustedSenders",
    });
    expect(clearTrusted.status).toBe(200);
    expect((await clearTrusted.json()).removed).toBe(1);
    policy = await readPolicy(context, accountId);
    expect(policy.trustedSenders).toEqual([]);

    const legacy = await mutate(context, `/api/accounts/${accountId}/personal-policy/import`, {
      mode: "replace",
      document: legacyPolicyDocument(),
    });
    expect(legacy.status).toBe(200);
    policy = await readPolicy(context, accountId);
    expect(policy.blockedSenders).toEqual(["blocked@policy.example"]);
    expect(policy.catchTrashSenders).toEqual([]);
    expect(policy.catchTrashDomains).toEqual([]);

    const badReset = await mutate(context, `/api/accounts/${accountId}/personal-policy/reset`, {
      confirmation: "RESET",
    });
    expect(badReset.status).toBe(400);
    expect((await readPolicy(context, accountId)).blockedSenders).toEqual(["blocked@policy.example"]);

    const reset = await mutate(context, `/api/accounts/${accountId}/personal-policy/reset`, {
      confirmation: PERSONAL_POLICY_RESET_CONFIRMATION,
    });
    expect(reset.status).toBe(200);
    expect((await reset.json()).removed).toBeGreaterThan(0);
    policy = await readPolicy(context, accountId);
    expect(policy).toMatchObject({
      blockedSenders: [],
      blockedDomains: [],
      catchTrashSenders: [],
      catchTrashDomains: [],
      trustedSenders: [],
      approvedExceptions: [],
      unsubscribedActions: [],
      reportedCampaigns: [],
    });

    const disconnected = await mutate(context, `/api/accounts/${accountId}`, {}, "DELETE");
    expect(disconnected.status).toBe(204);
  });
});
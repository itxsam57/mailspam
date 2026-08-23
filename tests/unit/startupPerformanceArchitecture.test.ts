import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (path: string): string => readFileSync(resolve(root, path), "utf8");

describe("desktop startup performance architecture", () => {
  it("starts development entry points directly instead of compiling the whole server first", () => {
    const pkg = JSON.parse(read("server/package.json")) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.dev).toBe("tsx src/index.ts");
    expect(pkg.scripts?.["dev:community"]).toBe("tsx src/communityIndex.ts");
    expect(pkg.scripts?.["dev:account-service"]).toBe("tsx src/accountServiceIndex.ts");
    expect(pkg.scripts?.start).toBe("node dist/index.js");
  });

  it("launches the workspace dev process without spawning npm.cmd directly on Windows", () => {
    const launcher = read("scripts/dev.mjs");
    const captureIndex = launcher.indexOf("const npmExecPath = process.env.npm_execpath?.trim()");
    const localEnvIndex = launcher.indexOf("parseEnv(readFileSync(envFile, \"utf8\"))");

    expect(captureIndex).toBeGreaterThanOrEqual(0);
    expect(localEnvIndex).toBeGreaterThan(captureIndex);
    expect(launcher).toContain("command = process.execPath");
    expect(launcher).toContain('[npmExecPath, "run", "dev", "-w", "server"]');
    expect(launcher).not.toContain('const npm = process.platform === "win32" ? "npm.cmd" : "npm"');
    expect(launcher).not.toContain('spawn("npm.cmd"');
    expect(launcher).toContain('process.env.ComSpec?.trim() || "cmd.exe"');
  });

  it("makes repository .env.local authoritative for source owner configuration and reports only credential presence", () => {
    const launcher = read("scripts/dev.mjs");
    expect(launcher).toContain('import { parseEnv } from "node:util"');
    expect(launcher).toContain('parseEnv(readFileSync(envFile, "utf8"))');
    expect(launcher).toContain("process.env[key] = value");
    expect(launcher).toContain("EMAIL_SHIELD_GOOGLE_CLIENT_ID");
    expect(launcher).toContain("EMAIL_SHIELD_GOOGLE_CLIENT_SECRET");
    expect(launcher).toContain("Google client ID ${googleClientIdLoaded ? \"loaded\" : \"missing\"}");
    expect(launcher).toContain("Google client secret ${googleClientSecretLoaded ? \"loaded\" : \"missing\"}");
    expect(launcher).not.toContain("console.log(process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET");
    expect(launcher).not.toContain('import { loadEnvFile } from "node:process"');
    expect(launcher).not.toContain("loadEnvFile(envFile)");
  });

  it("initializes independent protected repositories in one awaited concurrent phase", () => {
    const source = read("server/src/index.ts");
    const vault = source.indexOf("const credentialVault = getRuntimeCredentialVault()");
    const concurrentPhase = source.indexOf("const initialized = await Promise.all([");
    const completion = source.indexOf("] as const);", concurrentPhase);
    const listen = source.indexOf("app.listen(");

    expect(vault).toBeGreaterThanOrEqual(0);
    expect(concurrentPhase).toBeGreaterThan(vault);
    expect(completion).toBeGreaterThan(concurrentPhase);
    expect(listen).toBeGreaterThan(completion);
    expect(source).toContain("initializeDefaultPersonalPolicyRepository({ credentialVault })");
    expect(source).toContain("initializeDefaultAccountPlatform({ credentialVault, dataDirectory })");
    expect(source).toContain("createDefaultInboundEventStateRepository({ credentialVault, dataDirectory })");
    expect(source).toContain("createDefaultLiveConnectionPersistence({ credentialVault, dataDirectory })");
  });

  it("defers dashboard modules so HTML parsing and first paint are not blocked by module downloads", () => {
    const source = read("server/src/api/dashboardScripts.ts");
    expect(source).toContain('<script defer src="${path}"></script>');
    expect(source).not.toContain('`<script src="${path}"></script>`');
  });

  it("keeps secondary dashboard hydration route-lazy", () => {
    const operations = read("web/operations-dashboard.js");
    const billing = read("web/billing-plan-ui.js");
    const guardian = read("web/family-guardian-preferences.js");

    expect(operations).toContain("event.detail?.route === 'settings'");
    expect(operations).toContain("email-shield-developer-ui-enabled");
    expect(operations).toContain("loadWhenVisible()");
    expect(operations).not.toContain("event.detail?.route === 'community'");
    expect(billing).toContain("event.detail?.route === 'account'");
    expect(billing).not.toContain("setTimeout(mount, 350)");
    expect(guardian).toContain("event.detail?.route === 'family'");
    expect(guardian).not.toContain("setTimeout(() => { void load(); }, 600)");
  });
});

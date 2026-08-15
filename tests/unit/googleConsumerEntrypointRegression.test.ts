import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (path: string): string => readFileSync(resolve(root, path), "utf8");

describe("Google consumer mailbox entrypoint", () => {
  it("renders a real Google consumer option and binds it to the hardened Gmail OAuth owner", () => {
    const product = read("web/consumer-product.js");
    const onboarding = read("web/consumer-provider-onboarding.js");
    const oauth = read("web/gmail-oauth.js");

    expect(product).toContain("['gmail', 'Continue with Google', 'Gmail · browser OAuth', true]");
    expect(onboarding).toContain("['Continue with Google', 'gmail']");
    expect(onboarding).toContain("const owner = window.emailShieldGoogleOAuth");
    expect(onboarding).toContain("void owner.start()");
    expect(oauth).toContain("Object.defineProperty(window, 'emailShieldGoogleOAuth'");
  });

  it("never turns Google readiness into an unclickable native disabled provider card", () => {
    const onboarding = read("web/consumer-provider-onboarding.js");

    expect(onboarding).toContain("button.dataset.oauthConfigured = String(configured)");
    expect(onboarding).toContain("button.disabled = false");
    expect(onboarding).toContain("button.setAttribute('aria-disabled', 'false')");
    expect(onboarding).not.toContain("button.disabled = !configured");
    expect(onboarding).not.toContain("if (button.dataset.oauthConfigured !== 'true')");
  });

  it("rechecks protected Google readiness from the user click instead of permanently caching one failed startup probe", () => {
    const oauth = read("web/gmail-oauth.js");

    expect(oauth).toContain("if (googleConfigured !== true)");
    expect(oauth).toContain("const configured = await loadConfiguration()");
    expect(oauth).toContain("Google sign-in is not configured in this running Email Shield session");
    expect(oauth).not.toContain("if (googleConfigured === false) {\n      setStatus('Google sign-in is unavailable in this build.');\n      return;");
  });

  it("keeps the server as the final fail-closed authority for Google configuration", () => {
    const server = read("server/src/api/localDesktopServer.ts");
    const flow = read("server/src/oauth/googleOAuthFlow.ts");

    expect(server).toContain('app.get("/api/accounts/oauth/google/config"');
    expect(server).toContain("configured: googleOAuth.configured()");
    expect(server).toContain('app.post("/api/accounts/oauth/google/start"');
    expect(flow).toContain("return Boolean(this.options.clientId.trim() && resolveGoogleClientSecret(this.options.clientSecret))");
    expect(flow).toContain("client_secret: clientSecret");
  });
});

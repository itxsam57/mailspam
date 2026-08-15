import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("accessible localized safety interface", () => {
  it("provides keyboard, focus, status, table, motion, contrast and narrow-layout semantics", () => {
    const html = read("web/index.html");
    const scanMonitor = read("web/scan-monitor.js");
    const safeAudit = read("web/safe-audit.js");
    const policy = read("web/policy-management.js");

    expect(html).toContain('class="skip-link" href="#mainContent"');
    expect(html).toContain('<main id="mainContent" tabindex="-1">');
    expect(html).toContain(':focus-visible');
    expect(html).toContain('prefers-reduced-motion: reduce');
    expect(html).toContain('forced-colors: active');
    expect(html).toContain('@media (max-width: 680px)');
    expect(html).toContain('<label class="field" for="providerSelect">');
    expect(html).toContain('<label class="field" for="modeSelect">');
    expect(html).toContain('id="counters" role="status" aria-live="polite"');
    expect(html).toContain('role="listitem" aria-label=');
    expect(html).toContain('role="list" aria-label="Detection layer results"');
    expect(html).toContain("button.setAttribute('aria-pressed', String(selected))");
    expect(html).toContain("button.setAttribute('aria-current', 'true')");
    expect(scanMonitor).toContain('aria-atomic');
    expect(scanMonitor).toContain("scanPanel.setAttribute('aria-busy', 'true')");
    expect(scanMonitor).toContain("scanPanel.setAttribute('aria-busy', 'false')");
    expect(scanMonitor).toContain('<caption class="visually-hidden">');
    expect(scanMonitor).toContain('<th scope="col">');
    expect(safeAudit).toContain('<caption class="visually-hidden">');
    expect(policy).toContain('aria-live="polite"');
    expect(policy).toContain('<label class="field" for="policySearch">');
  });

  it("uses a strict extensible catalog and locale-aware date/number formatters", () => {
    const source = read("web/i18n.js");
    const operations = read("web/operations-dashboard.js");
    const elements: Array<{ textContent?: string; setAttribute: (name: string, value: string) => void; getAttribute: (name: string) => string }> = [];
    const documentElement = { lang: "", dataset: {} as Record<string, string> };
    const document = {
      documentElement,
      readyState: "complete",
      querySelectorAll: () => elements,
      addEventListener: () => undefined,
    };
    const window: Record<string, unknown> = {};
    vm.runInNewContext(source, { window, document, navigator: { language: "en-US" }, Intl, Date, Number, Object, Map });
    const api = window.emailShieldI18n as {
      t: (key: string, values?: Record<string, unknown>) => string;
      register: (locale: string, catalog: Record<string, string>) => void;
      setLocale: (locale: string) => string;
      formatDate: (value: unknown) => string;
      formatNumber: (value: unknown) => string;
      locale: () => string;
    };

    expect(api.locale()).toBe("en");
    expect(api.t("scan.quick")).toBe("Quick Scan");
    expect(api.t("missing.message")).toBe("[missing.message]");
    expect(api.t("operations.summary", {
      feed: "verified",
      feedEntries: 2,
      pending: 1,
      falsePositive: 3,
      abuseAccepted: 4,
      abuseFailed: 5,
      background: 6,
    })).toBe("Feed: verified (2 entries); queued privacy-reduced reports: 1; message-level Safe approvals: 3; scam reports accepted/failed: 4/5; scheduled accounts: 6.");
    expect(api.t("operations.updated", { date: "Aug 12" })).toBe("Aggregate operations refreshed Aug 12.");
    expect(operations).toContain("const t = (key, values) => i18n?.t(key, values) || key;");
    expect(operations).toContain("summary.textContent = t('operations.summary', {");
    expect(operations).toContain("status.textContent = t('operations.updated', { date:");
    api.register("fr", { "scan.quick": "Analyse rapide", "test.hello": "Bonjour {name}" });
    expect(api.setLocale("fr-FR")).toBe("fr");
    expect(documentElement.lang).toBe("fr");
    expect(api.t("scan.quick")).toBe("Analyse rapide");
    expect(api.t("test.hello", { name: "Sam" })).toBe("Bonjour Sam");
    expect(api.t("scan.full")).toBe("Full Mailbox Audit");
    expect(api.formatNumber(1234)).toMatch(/1.*234/);
    expect(api.formatDate("2026-08-11T12:00:00Z")).not.toBe("—");
    expect(() => api.register("fr", { invalid: "bad" })).toThrow(/invalid message/);
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("sessionStorage");
  });

  it("loads localization before application code and removes third-party font requests", () => {
    const html = read("web/index.html");
    const server = read("server/src/api/localDesktopServer.ts");
    expect(html.indexOf('<script src="/i18n.js"></script>')).toBeLessThan(html.indexOf("const API = ''"));
    expect(html).not.toContain("fonts.googleapis.com");
    expect(html).not.toContain("fonts.gstatic.com");
    expect(server).not.toContain("fonts.googleapis.com");
    expect(server).not.toContain("fonts.gstatic.com");
    expect(server).toContain('"font-src \'self\'"');
  });

  it("teaches the safety boundaries without promising complete protection", () => {
    const html = read("web/index.html");
    expect(html).toContain('id="safetyEducation"');
    expect(html).toContain("Unknown or partial means inspection was incomplete");
    expect(html).toContain("never treat it as Safe");
    expect(html).toContain("Do not reply, call a number in the message, pay");
    expect(html).toContain("one-time code, recovery code, or seed phrase");
    expect(html).toContain("Report Scam saves an account-local campaign rule and moves the current message to Trash after provider confirmation");
    expect(html).toContain("future campaign matches are auto-moved for this account");
    expect(html).toContain("Global Shield thresholds remain independent");
    expect(html).toContain("Analyze Links is explicit and never uses mailbox cookies or provider credentials");
    expect(html).toContain("Urgency is a reason to slow down");
    expect(html).not.toMatch(/(?:guaranteed|100%) safe/i);
  });
});
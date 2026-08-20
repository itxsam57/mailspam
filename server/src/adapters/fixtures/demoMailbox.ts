import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FixtureAdapter,
  type FixtureFolderOverrides,
  type FixtureMessage,
} from "./fixtureAdapter.js";
import type { Provider } from "../../canonical/envelope.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, "../../../../fixtures/scam-corpus");
const HEALTH_CLEANUP_FIXTURE_ID = "health-cleanup-old-newsletter";
const HEALTH_CLEANUP_OLD_NEWSLETTER = `From: "RealNews Weekly" <newsletter@realnewsco.com>
To: user@example-mailbox.test
Subject: Archived weekly digest fixture
Date: Mon, 01 Jun 2026 12:04:13 GMT
Message-ID: <health-cleanup-old@fixture.test>
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
List-ID: <weekly.realnewsco.com>
List-Unsubscribe: <https://realnewsco.com/unsubscribe?one-click=true>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Fixture-only older newsletter used to exercise explicit Inbox Health cleanup.\n`;

const HEALTH_SECURITY_ALERT_FIXTURES: readonly FixtureMessage[] = Object.freeze([
  {
    id: "health-security-signin-a",
    rawEml: `From: "Google" <no-reply@accounts.google.com>
To: user@example-mailbox.test
Subject: Security alert: new sign-in
Date: Thu, 20 Aug 2026 10:00:00 GMT
Message-ID: <health-security-signin-a@fixture.test>
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

A new sign-in was detected on your account.\n`,
    folder: "inbox",
    providerFolderName: "INBOX",
    authenticationTrust: "trusted",
  },
  {
    id: "health-security-signin-b",
    rawEml: `From: "Google" <no-reply@accounts.google.com>
To: user@example-mailbox.test
Subject: New sign-in on your account
Date: Thu, 20 Aug 2026 12:00:00 GMT
Message-ID: <health-security-signin-b@fixture.test>
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Security alert for a new sign-in.\n`,
    folder: "inbox",
    providerFolderName: "INBOX",
    authenticationTrust: "trusted",
  },
  {
    id: "health-security-password",
    rawEml: `From: "Google" <no-reply@accounts.google.com>
To: user@example-mailbox.test
Subject: Password changed
Date: Thu, 20 Aug 2026 13:00:00 GMT
Message-ID: <health-security-password@fixture.test>
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Your account password changed recently.\n`,
    folder: "inbox",
    providerFolderName: "INBOX",
    authenticationTrust: "trusted",
  },
]);

interface ManifestEntry { category: string; kind: "malicious" | "legit"; file: string; variant: string; authenticationTrust: "trusted" | "unknown" }

/**
 * Builds a demo mailbox from the synthetic scam corpus: malicious "plain"
 * variants land in Inbox (as if they slipped past provider spam filtering,
 * which is the realistic case this app targets) and Spam; legit controls
 * land in Inbox. When the explicit development entitlement is enabled, one
 * additional old newsletter gives executable Health acceptance a deterministic
 * >30-day cleanup target without modifying the detection corpus or normal
 * fixture-domain baselines. A second, independently opt-in Gmail-only Health
 * security fixture set is reserved for browser acceptance of authenticated
 * provider-alert composition and is never enabled by normal fixture startup.
 * Fixture folder mutations are held in the account session so a provider-
 * confirmed move remains visible on the next scan.
 *
 * The corpus is controlled test input. Its Authentication-Results values model
 * provider-produced outcomes and are therefore marked trusted explicitly here;
 * the development-only Health samples are also explicit trusted synthetic input.
 */
export function buildDemoMailbox(
  provider: Provider,
  folderOverrides: FixtureFolderOverrides = {},
): FixtureAdapter {
  const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf-8"));
  const plainOnly = manifest.filter((m) => m.variant === "plain");
  let maliciousIndex = 0;

  const messages: FixtureMessage[] = plainOnly.map((entry, i) => {
    const rawEml = readFileSync(join(CORPUS_DIR, entry.file), "utf-8");
    const id = `${entry.category}-${entry.kind}-${i}`;

    if (entry.kind === "malicious") {
      const defaultFolder = maliciousIndex++ % 2 === 0 ? ("inbox" as const) : ("spam" as const);
      const folder = folderOverrides[id] ?? defaultFolder;
      return {
        id,
        rawEml,
        folder,
        providerFolderName: folder === "inbox" ? "INBOX" : folder === "spam" ? "Spam" : "Trash",
        authenticationTrust: entry.authenticationTrust,
      };
    }

    const folder = folderOverrides[id] ?? ("inbox" as const);
    return {
      id,
      rawEml,
      folder,
      providerFolderName: folder === "inbox" ? "INBOX" : folder === "spam" ? "Spam" : "Trash",
      authenticationTrust: entry.authenticationTrust,
    };
  });

  if (process.env.EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS === "1") {
    const healthCleanupFolder = folderOverrides[HEALTH_CLEANUP_FIXTURE_ID] ?? ("inbox" as const);
    messages.push({
      id: HEALTH_CLEANUP_FIXTURE_ID,
      rawEml: HEALTH_CLEANUP_OLD_NEWSLETTER,
      folder: healthCleanupFolder,
      providerFolderName: healthCleanupFolder === "inbox" ? "INBOX" : healthCleanupFolder === "spam" ? "Spam" : "Trash",
      authenticationTrust: "trusted",
    });
  }

  if (provider === "gmail" && process.env.EMAIL_SHIELD_ENABLE_HEALTH_SECURITY_ALERT_FIXTURES === "1") {
    for (const fixture of HEALTH_SECURITY_ALERT_FIXTURES) {
      const folder = folderOverrides[fixture.id] ?? fixture.folder;
      messages.push({
        ...fixture,
        folder,
        providerFolderName: folder === "inbox" ? "INBOX" : folder === "spam" ? "Spam" : "Trash",
      });
    }
  }

  return new FixtureAdapter(provider, messages, folderOverrides);
}

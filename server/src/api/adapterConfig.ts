import type { Provider } from "../canonical/envelope.js";
import type { EmailAdapter } from "../canonical/adapter.js";
import { buildDemoMailbox } from "../adapters/fixtures/demoMailbox.js";
import { GmailAdapter, type GmailOAuthCredentials } from "../adapters/gmail/gmailAdapter.js";
import { OutlookAdapter, type OutlookOAuthCredentials } from "../adapters/outlook/outlookAdapter.js";
import { createGenericImapAdapter, createIcloudAdapter, createYahooAdapter, type ImapCredentials } from "../adapters/imap/imapAdapter.js";

export type AdapterConfig =
  | { provider: Provider; mode: "fixture" }
  | { provider: "gmail"; mode: "live"; credentials: GmailOAuthCredentials }
  | { provider: "outlook"; mode: "live"; credentials: OutlookOAuthCredentials }
  | { provider: "icloud" | "yahoo"; mode: "live"; credentials: { user: string; appPassword: string } }
  | { provider: "imap"; mode: "live"; credentials: ImapCredentials };

export function createAdapter(config: AdapterConfig): EmailAdapter {
  if (config.mode === "fixture") return buildDemoMailbox(config.provider);
  switch (config.provider) {
    case "gmail": return new GmailAdapter(config.credentials);
    case "outlook": return new OutlookAdapter(config.credentials);
    case "icloud": return createIcloudAdapter(config.credentials.user, config.credentials.appPassword);
    case "yahoo": return createYahooAdapter(config.credentials.user, config.credentials.appPassword);
    case "imap": return createGenericImapAdapter(config.credentials);
  }
}

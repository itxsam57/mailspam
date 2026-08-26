// Owner live acceptance only. This launcher enables the existing development
// entitlement boundary without creating or forcing a fixture mailbox/provider.
// Real Gmail/iCloud configuration continues to come from the normal .env.local
// and connection flows loaded by dev.mjs.
if (!process.argv.includes("--email-shield-owner-qa")) {
  process.argv.push("--email-shield-owner-qa");
}
if (process.env.EMAIL_SHIELD_RUNTIME_TRACE === undefined) {
  process.env.EMAIL_SHIELD_RUNTIME_TRACE = "1";
}
await import("./dev.mjs");

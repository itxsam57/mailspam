// Owner/engineering acceptance only. The dedicated argv signal is consumed by
// dev.mjs after .env.local is loaded, so project-local configuration cannot
// accidentally enable this mode during normal startup or disable it here.
if (!process.argv.includes("--email-shield-fixtures")) {
  process.argv.push("--email-shield-fixtures");
}
if (process.env.EMAIL_SHIELD_RUNTIME_TRACE === undefined) {
  process.env.EMAIL_SHIELD_RUNTIME_TRACE = "1";
}
await import("./dev.mjs");

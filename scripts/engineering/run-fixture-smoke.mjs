const allowedTargets = new Set([
  "./smoke-server.mjs",
  "./smoke-browser-scan-results.mjs",
]);

const target = process.argv[2];
if (!target || !allowedTargets.has(target)) {
  throw new Error("Fixture smoke launcher accepts only the registered engineering fixture smokes.");
}

// Fixture/developer routes are intentionally fail-closed in normal consumer
// startup. Engineering smokes that exercise fixture mailboxes must opt in
// explicitly, in-process, before importing the harness that spawns the server.
process.env.EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS = "1";
await import(new URL(target, import.meta.url));

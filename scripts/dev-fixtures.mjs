// Owner/engineering acceptance only. Normal consumer startup intentionally keeps
// development entitlements disabled so Fixture mode and developer routes are not
// exposed to a production-like consumer session.
process.env.EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS = "1";
await import("./dev.mjs");

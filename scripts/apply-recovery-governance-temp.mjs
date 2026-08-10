import { readFileSync, writeFileSync } from "node:fs";

function replaceOnce(text, needle, replacement, label) {
  const index = text.indexOf(needle);
  if (index < 0) throw new Error(`${label} insertion point not found`);
  if (text.indexOf(needle, index + needle.length) >= 0) throw new Error(`${label} insertion point is not unique`);
  return text.slice(0, index) + replacement + text.slice(index + needle.length);
}

{
  const path = ".engineering/TEST_MATRIX.md";
  let text = readFileSync(path, "utf8");
  if (!text.includes("| A-50 |")) {
    const row = "| A-49 | Bounded signed community-feed resources | Remote report receipts are capped at 32 KiB and signed feed/cache documents at 4 MiB using streamed byte accounting before JSON parsing; v1 signed feeds are schema/entry/string/fan-out bounded before detector use; Ed25519 signatures must decode canonically to exactly 64 bytes; oversized/invalid feeds become unavailable rather than clean or truncated; a still-fresh verified cache may survive a bad refresh; durable report acceptance is not reversed by later feed-capacity publication failure; no provider/mailbox permission or public-deployment claim is added | `communityFeedBounds.test.ts`, `communityFeedCapacitySemantics.test.ts`, community signing/network/API/architecture regressions, strict type/build, full corpus/Worker/server/browser gate | Windows + macOS + Ubuntu | Blocking |";
    const next = row + "\n| A-50 | Community disaster recovery and signing-rotation preparation | Portable community recovery uses a bounded AES-256-GCM envelope with reviewed scrypt derivation, strict authoritative-file manifests and descriptor-bound no-follow source reads; CLI backup secrets come only from an owner-only passphrase file and never argv; restore targets must be new paths and are staged, cryptographically/store-validated, then atomically cut over; rotation preparation generates and self-verifies a distinct next Ed25519 pair plus public overlap manifest while leaving the active signer unchanged; no CI result may claim the production restore/rotation ceremony completed | `communityRecoveryOperations.test.ts`, community signing/storage/network regressions, strict type/build, compiled operations smoke through build, full corpus/Worker/server/browser gate | Windows + macOS + Ubuntu | Blocking |";
    text = replaceOnce(text, row, next, "A-50");
  }
  const oldAutomation = "PSL-backed registrable-domain boundary behavior, bounded signed community-feed acquisition/validation behavior, and Analyze Links DNS-pinning/SSRF/redirect/resource-boundary behavior are automated.";
  const newAutomation = "PSL-backed registrable-domain boundary behavior, bounded signed community-feed acquisition/validation behavior, community encrypted-recovery/signing-rotation preparation behavior, and Analyze Links DNS-pinning/SSRF/redirect/resource-boundary behavior are automated.";
  if (text.includes(oldAutomation)) text = replaceOnce(text, oldAutomation, newAutomation, "automated handoff");
  writeFileSync(path, text);
}

{
  const path = ".engineering/REGRESSION_REGISTER.md";
  let text = readFileSync(path, "utf8");
  if (!text.includes("| REG-060 |")) {
    const row = "| REG-059 | LOCKED | Community network acquisition and signed-feed consumption must remain resource bounded before detector use. Remote receipts are limited to 32 KiB and feed/cache documents to 4 MiB with both declared-length and streamed-byte enforcement; version-1 feed entries, values, rule IDs and identity alias/domain fan-out are bounded and unknown fields rejected; Ed25519 signatures must be canonical 64-byte values; oversized/invalid feeds are unavailable, never clean or silently truncated; only an independently still-valid cached feed may be retained; a durably accepted report must not be falsely rejected/requeued solely because publication subsequently reaches the feed resource ceiling. | `communityFeedBounds.test.ts`, `communityFeedCapacitySemantics.test.ts`, community signing/network/API/architecture regressions, strict type/build, full corpus/Worker/server/browser gate |";
    const next = row + "\n| REG-060 | LOCKED | Community disaster recovery and signing-key rotation preparation must remain secret-safe, bounded and non-destructive. Portable backups use the reviewed AES-256-GCM+scrypt envelope, contain only authoritative aggregate/signing state, enforce strict known-file/hash/resource rules and never accept passphrases in argv; POSIX passphrase and sensitive source reads use same-descriptor no-follow checks with owner-only passphrase permissions. Restore must target a new path, validate the real signer/store in staging and atomically rename only after success. Rotation preparation must create a distinct self-verifying next Ed25519 pair/public overlap manifest while leaving the active signer unchanged and never placing private material in the public manifest or CLI JSON. Production restore and key-switchover ceremonies remain live GAP-004 acceptance. | `communityRecoveryOperations.test.ts`, strict type/build, full Windows/macOS/Ubuntu engineering gate |";
    text = replaceOnce(text, row, next, "REG-060");
  }
  if (!text.includes("| GAP-019 |")) {
    const row = "| GAP-018 | RESOLVED | Bounded community-feed acquisition and signed-document validation | The remote client formerly parsed community JSON without a response-byte ceiling and verified signed feeds without a bounded v1 entry schema, so a compromised/misconfigured endpoint or pathological signed document could consume excessive memory/CPU before or after signature validation. Added streamed 32 KiB receipt / 4 MiB feed limits, bounded cache reads, strict signed-entry/fan-out/signature validation, signer-side document limits, verified-cache failover, and capacity-safe report acceptance semantics. GAP-004 public deployment/ops and GAP-008 gateway reputation/volumetric defence remain open and are not claimed by this resolution. |";
    const next = row + "\n| GAP-019 | RESOLVED | Community disaster-recovery and signing-rotation preparation tooling | The repository had no operator-grade way to produce an encrypted portable backup of authoritative aggregate/signing state, validate a restore before cutover, or prepare a controlled two-key Ed25519 overlap package. Added bounded AES-256-GCM+scrypt recovery bundles, strict authenticated manifests, descriptor-bound secret/source reads, atomic new-path restore after real signer/store validation, a passphrase-file-only CLI, and self-verifying next-key/public-overlap rotation packages that do not replace the active signer. This resolves missing tooling only: GAP-004 remains open until a deployed backup/restore drill and real key overlap/switchover/retirement ceremony are executed. |";
    text = replaceOnce(text, row, next, "GAP-019");
  }
  writeFileSync(path, text);
}

{
  const path = "README_REBUILD_STATUS.md";
  let text = readFileSync(path, "utf8");
  if (!text.includes("encrypted community disaster-recovery tooling")) {
    const row = "- bounded signed community-feed acquisition and validation: streamed 32 KiB receipt / 4 MiB feed ceilings, strict v1 entry and identity fan-out bounds, exact Ed25519 signature encoding, verified-cache failover, and capacity-safe accepted-report semantics without claiming public deployment or gateway abuse controls.";
    const next = "- bounded signed community-feed acquisition and validation: streamed 32 KiB receipt / 4 MiB feed ceilings, strict v1 entry and identity fan-out bounds, exact Ed25519 signature encoding, verified-cache failover, and capacity-safe accepted-report semantics without claiming public deployment or gateway abuse controls;\n- encrypted community disaster-recovery tooling and signing-key rotation preparation: bounded authenticated recovery bundles, owner-only passphrase-file custody, validated atomic restore to a new data path, and self-verifying two-key overlap packages while production restore/rotation execution remains live deployment work.";
    text = replaceOnce(text, row, next, "README brick");
  }
  writeFileSync(path, text);
}

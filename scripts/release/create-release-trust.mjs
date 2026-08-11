import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  assertReleaseTrustStore,
  releaseKeyId,
  RELEASE_TRUST_SCHEMA,
} from "./release-lifecycle-lib.mjs";
import { writeNormalizedText } from "./portable-package-lib.mjs";

const separator = process.argv.indexOf("--output");
if (separator < 2 || separator !== process.argv.length - 2) {
  throw new Error("Usage: create-release-trust.mjs <public-key.pem> [next-key.pem ...] --output <release-trust.json>");
}
const paths = process.argv.slice(2, separator);
if (paths.length < 1 || paths.length > 4) throw new Error("Release trust store requires one to four public keys.");
const keys = paths.map((path) => {
  const absolute = resolve(path);
  const state = lstatSync(absolute);
  if (!state.isFile() || state.isSymbolicLink() || state.size < 80 || state.size > 8_192) {
    throw new Error("Release public keys must be bounded regular files.");
  }
  const publicKeyPem = readFileSync(absolute, "utf8");
  return { keyId: releaseKeyId(publicKeyPem), publicKeyPem };
});
const trustStore = { schemaVersion: RELEASE_TRUST_SCHEMA, product: "Email Shield", keys };
assertReleaseTrustStore(trustStore);
const output = resolve(process.argv[separator + 1]);
writeNormalizedText(output, `${JSON.stringify(trustStore, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ trustStore: output, keyIds: keys.map((entry) => entry.keyId) })}\n`);

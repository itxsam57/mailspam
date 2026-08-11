import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  MAX_REGRESSION_SAMPLE_BYTES,
  approveRegressionCandidate,
  intakeRegressionSample,
  verifyRegressionVault,
} from "../../server/dist/devtools/regressionVault.js";

function fail(message) {
  console.error(`Regression Vault: ${message}`);
  process.exit(1);
}

function argumentsFor(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) fail(`unexpected argument ${token}`);
    if (token === "--attest-no-private-content") { values.set(token, true); continue; }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) fail(`${token} requires a value`);
    if (values.has(token)) fail(`${token} may be supplied only once`);
    values.set(token, value);
    index += 1;
  }
  return values;
}

function required(values, key) {
  const value = values.get(key);
  if (typeof value !== "string" || !value) fail(`${key} is required`);
  return value;
}

function boundedRegularFile(path) {
  const absolute = resolve(path);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) fail("sample input must be a regular non-symbolic file");
  if (stat.size < 1 || stat.size > MAX_REGRESSION_SAMPLE_BYTES) fail(`sample input must be 1-${MAX_REGRESSION_SAMPLE_BYTES} bytes`);
  return readFileSync(absolute, "utf8");
}

const [command, ...argv] = process.argv.slice(2);
const values = argumentsFor(argv);
const dataRoot = resolve(process.env.EMAIL_SHIELD_DATA_DIR?.trim() || ".email-shield-data");
const candidateRoot = resolve(values.get("--candidate-root") || `${dataRoot}/regression-vault-intake`);
const vaultRoot = resolve(values.get("--vault-root") || "fixtures/regression-vault/v1");

if (command === "intake") {
  const candidate = intakeRegressionSample({
    candidateRoot,
    rawEml: boundedRegularFile(required(values, "--file")),
    category: required(values, "--category"),
    kind: required(values, "--kind"),
    expectedVerdict: required(values, "--expected"),
    authenticationTrust: required(values, "--authentication-trust"),
    attestedNoPrivateContent: values.get("--attest-no-private-content") === true,
  });
  console.log(JSON.stringify({ candidateRoot, candidate }, null, 2));
} else if (command === "approve") {
  const result = await approveRegressionCandidate({
    candidateRoot,
    candidateId: required(values, "--candidate-id"),
    reviewDigest: required(values, "--review-digest"),
    reviewerRole: required(values, "--reviewer-role"),
    vaultRoot,
  });
  console.log(JSON.stringify({ vaultRoot, ...result }, null, 2));
} else if (command === "verify") {
  const results = await verifyRegressionVault(vaultRoot);
  console.log(`Regression Vault passed: ${results.length} approved samples x 5 providers.`);
} else {
  fail("use intake, approve or verify");
}

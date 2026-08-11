import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildCapacityPlan } from "../../server/dist/operations/capacityPlan.js";

const known = new Set(["--profile", "--compute-instance-hour", "--storage-gib-month", "--egress-gib", "--request-million"]);
const options = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  const value = process.argv[index + 1];
  if (!known.has(name)) throw new Error(`Unknown capacity-plan option: ${name}`);
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value.`);
  if (options.has(name)) throw new Error(`${name} may be supplied only once.`);
  options.set(name, value);
}
function numericOption(name) {
  return options.has(name) ? Number(options.get(name)) : null;
}

const profilePath = resolve(options.get("--profile") || "config/capacity/v1/community-baseline.json");
const workload = JSON.parse(readFileSync(profilePath, "utf8"));
const priceNames = ["--compute-instance-hour", "--storage-gib-month", "--egress-gib", "--request-million"];
const supplied = priceNames.map(numericOption);
if (supplied.some((value) => value !== null) && supplied.some((value) => value === null)) {
  throw new Error("Supply all four unit prices or none of them.");
}
const prices = supplied[0] === null ? null : {
  computeInstanceHour: supplied[0],
  storageGibMonth: supplied[1],
  egressGib: supplied[2],
  requestMillion: supplied[3],
};
process.stdout.write(`${JSON.stringify(buildCapacityPlan(workload, prices), null, 2)}\n`);

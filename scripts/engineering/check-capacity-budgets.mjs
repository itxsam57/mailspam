import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { buildCapacityPlan } from "../../server/dist/operations/capacityPlan.js";

const workload = JSON.parse(readFileSync(resolve("config/capacity/v1/community-baseline.json"), "utf8"));
const plan = buildCapacityPlan(workload, {
  computeInstanceHour: 0.25,
  storageGibMonth: 0.10,
  egressGib: 0.08,
  requestMillion: 1.00,
});
if (!plan.projection.withinSeventyPercentStoragePlanningTarget) throw new Error("Baseline workload exceeds the 70% authoritative-storage planning target.");
if (plan.applicationBudgets.authoritativeSourceBytes !== 192 * 1024 * 1024) throw new Error("Authoritative recovery/runtime storage budget drifted.");
if (plan.applicationBudgets.destinationConcurrency !== 4 || plan.applicationBudgets.destinationQueue !== 256 || plan.applicationBudgets.backgroundConcurrentScans !== 1) throw new Error("Bounded concurrency budget drifted.");
if (plan.applicationBudgets.reportRequestBytes !== 64 * 1024 || plan.applicationBudgets.feedResponseBytes !== 4 * 1024 * 1024) throw new Error("Network resource budget drifted.");
if (plan.estimatedMonthlyCost?.total !== 194.30875) throw new Error(`Deterministic cost arithmetic drifted: ${plan.estimatedMonthlyCost?.total}`);
console.log(`Capacity budget passed: ${plan.projection.dailyReports} modeled reports/day, ${plan.projection.projectedAuthoritativeUsagePercent}% storage planning use, ${plan.projection.monthlyFeedEgressGib} GiB/month modeled feed egress.`);

import { describe, expect, it } from "vitest";
import { assertCapacityWorkload, buildCapacityPlan } from "../../server/src/operations/capacityPlan.js";

const workload = {
  schemaVersion: 1 as const,
  clients: 10_000,
  averageReportsPerClientPerDay: 0.05,
  retentionDays: 90,
  averageReportBytes: 2_048,
  feedDownloadsPerClientPerDay: 1,
  averageFeedBytes: 512 * 1_024,
  computeInstances: 1,
  backupCopies: 3,
};

describe("deployment capacity and cost plan", () => {
  it("projects the reviewed baseline from runtime-owned budgets without claiming an SLA", () => {
    const plan = buildCapacityPlan(workload);
    expect(plan.projection).toMatchObject({
      dailyReports: 500,
      monthlyRequests: 15_000,
      projectedAuthoritativeUsagePercent: 45.776367,
      withinSeventyPercentStoragePlanningTarget: true,
      provisionedStorageGib: 0.75,
    });
    expect(plan.applicationBudgets).toMatchObject({
      reportRequestBytes: 65_536,
      feedResponseBytes: 4_194_304,
      authoritativeSourceBytes: 201_326_592,
      destinationConcurrency: 4,
      destinationQueue: 256,
      backgroundConcurrentScans: 1,
    });
    expect(plan.estimatedMonthlyCost).toBeNull();
    expect(plan.qualification).toContain("not_a_throughput_or_availability_sla");
  });

  it("uses only explicit operator prices and stable arithmetic", () => {
    const plan = buildCapacityPlan(workload, {
      computeInstanceHour: 0.25,
      storageGibMonth: 0.10,
      egressGib: 0.08,
      requestMillion: 1,
    });
    expect(plan.estimatedMonthlyCost).toEqual({
      compute: 182.5,
      storage: 0.075,
      egress: 11.71875,
      requests: 0.015,
      total: 194.30875,
      currency: "operator_supplied_units",
    });
  });

  it("rejects unknown fields, non-finite values and requests beyond application ceilings", () => {
    expect(() => assertCapacityWorkload({ ...workload, mailbox: "private" })).toThrow(/schema/);
    expect(() => buildCapacityPlan({ ...workload, averageReportBytes: 65_537 })).toThrow(/averageReportBytes/);
    expect(() => buildCapacityPlan({ ...workload, clients: Number.POSITIVE_INFINITY })).toThrow(/clients/);
    expect(() => buildCapacityPlan(workload, { computeInstanceHour: -1, storageGibMonth: 0, egressGib: 0, requestMillion: 0 })).toThrow(/computeInstanceHour/);
  });
});

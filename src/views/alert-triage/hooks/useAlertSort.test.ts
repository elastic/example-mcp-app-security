/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import { groupAlerts, sortAlerts } from "./useAlertSort.js";
import type { SecurityAlert } from "../../../shared/types.js";

function makeAlert(
  id: string,
  overrides: Partial<SecurityAlert["_source"]> = {}
): SecurityAlert {
  return {
    _id: id,
    _index: ".alerts-security.alerts-default",
    _source: {
      "@timestamp": "2024-01-01T00:00:00Z",
      "kibana.alert.rule.name": "R",
      "kibana.alert.rule.uuid": "r",
      "kibana.alert.severity": "low",
      "kibana.alert.risk_score": 21,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "x",
      ...overrides,
    },
  };
}

// `AlertsService.getAlerts()` normalizes ECS entity fields to scalars before
// this hook ever sees them, but these tests exercise the hook's own
// defense-in-depth guards directly — in case a stray array-shaped field ever
// reaches it via a different path (e.g. a future bootstrap/mock data source).
const arrayShapedHost = { name: ["sa-da-vm-lls-01"] } as unknown as { name: string };

describe("sortAlerts", () => {
  it("sorts by host without throwing when a host.name is an array", () => {
    const alerts = [
      makeAlert("a1", { host: { name: "zzz-host" } }),
      makeAlert("a2", { host: arrayShapedHost }),
    ];

    expect(() => sortAlerts(alerts, "host")).not.toThrow();
  });
});

describe("groupAlerts", () => {
  // Regression test: previously, an array-shaped host.name passed the
  // `!key || !name` truthiness guard (a non-empty array is truthy), then
  // crashed the group sort at `a.name.localeCompare(b.name)` — arrays have no
  // `.localeCompare`. This exact crash rendered the Alert Triage widget as a
  // blank panel with no error toast, against real alert data.
  it("groups by host without throwing when one alert's host.name is an array", () => {
    const alerts = [
      makeAlert("a1", { host: { name: "sa-da-ingest-01" } }),
      makeAlert("a2", { host: arrayShapedHost }),
    ];

    expect(() => groupAlerts(alerts, "host")).not.toThrow();
  });

  it("skips an alert whose host.name is an array rather than grouping it incorrectly", () => {
    const alerts = [
      makeAlert("a1", { host: { name: "sa-da-ingest-01" } }),
      makeAlert("a2", { host: arrayShapedHost }),
    ];

    const groups = groupAlerts(alerts, "host")!;
    expect(groups).toHaveLength(1);
    expect(groups[0].name).toBe("sa-da-ingest-01");
    expect(groups[0].alerts).toHaveLength(1);
  });

  it("groups normally when all host names are scalar strings", () => {
    const alerts = [
      makeAlert("a1", { host: { name: "host-b" } }),
      makeAlert("a2", { host: { name: "host-a" } }),
      makeAlert("a3", { host: { name: "host-a" } }),
    ];

    const groups = groupAlerts(alerts, "host")!;
    expect(groups.map((g) => g.name).sort()).toEqual(["host-a", "host-b"]);
    expect(groups.find((g) => g.name === "host-a")!.alerts).toHaveLength(2);
  });

  it("returns null for groupBy 'none'", () => {
    expect(groupAlerts([makeAlert("a1")], "none")).toBeNull();
  });
});

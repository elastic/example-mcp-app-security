/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { SpacesService } from "./spacesService.js";
import type { SpacesClient } from "../client/spacesClient.js";

const ALERTS_PATTERN = ".alerts-security.alerts-*";
const DISCOVERIES_PATTERN =
  ".alerts-security.attack.discovery.alerts-*,.adhoc.alerts-security.attack.discovery.alerts-*";

function makeService(configuredSpace = "ops") {
  const spacesClient = {
    listSpaces: vi.fn(),
    countBySpace: vi.fn().mockResolvedValue({}),
  };
  const service = new SpacesService({
    spacesClient: spacesClient as unknown as SpacesClient,
    configuredSpace,
  });
  return { spacesClient, service };
}

function expectedBody(days: number) {
  return {
    size: 0,
    track_total_hits: false,
    query: {
      bool: {
        filter: [
          { term: { "kibana.alert.workflow_status": "open" } },
          { range: { "@timestamp": { gte: `now-${days}d` } } },
        ],
      },
    },
    aggs: { by_space: { terms: { field: "kibana.space_ids", size: 100 } } },
  };
}

describe("SpacesService", () => {
  describe("listSpaces", () => {
    it("returns the accessible spaces alongside the configured space", async () => {
      const { spacesClient, service } = makeService("ops");
      const spaces = [
        { id: "default", name: "Default" },
        { id: "ops", name: "Ops", color: "#f00", initials: "OP" },
      ];
      spacesClient.listSpaces.mockResolvedValueOnce(spaces);

      await expect(service.listSpaces()).resolves.toEqual({ configured: "ops", spaces });
    });
  });

  describe("countBySpace", () => {
    it("counts open alerts over the last 7 days by default", async () => {
      const { spacesClient, service } = makeService();

      const out = await service.countBySpace("alerts");

      expect(spacesClient.countBySpace).toHaveBeenCalledExactlyOnceWith(
        ALERTS_PATTERN,
        expectedBody(7)
      );
      expect(out).toEqual({ kind: "alerts", days: 7, counts: {} });
    });

    it("counts open discoveries across scheduled and ad-hoc indices over the last day by default", async () => {
      const { spacesClient, service } = makeService();

      const out = await service.countBySpace("discoveries");

      expect(spacesClient.countBySpace).toHaveBeenCalledExactlyOnceWith(
        DISCOVERIES_PATTERN,
        expectedBody(1)
      );
      expect(out).toEqual({ kind: "discoveries", days: 1, counts: {} });
    });

    it("honours an explicit look-back window", async () => {
      const { spacesClient, service } = makeService();

      const out = await service.countBySpace("discoveries", 30);

      expect(spacesClient.countBySpace).toHaveBeenCalledWith(
        DISCOVERIES_PATTERN,
        expectedBody(30)
      );
      expect(out.days).toBe(30);
    });

    it("maps the per-space buckets to counts keyed by space id", async () => {
      const { spacesClient, service } = makeService();
      spacesClient.countBySpace.mockResolvedValueOnce({
        aggregations: {
          by_space: {
            buckets: [
              { key: "default", doc_count: 12 },
              { key: "soc", doc_count: 3 },
              { key: "__proto__", doc_count: 1 },
            ],
          },
        },
      });

      const out = await service.countBySpace("alerts", 7);

      expect(out.counts).toEqual({ default: 12, soc: 3, ["__proto__"]: 1 });
      expect(Object.keys(out.counts)).toEqual(["default", "soc", "__proto__"]);
      expect(Object.getPrototypeOf(out.counts)).toBe(Object.prototype);
    });

    it("returns empty counts when no index matched", async () => {
      const { spacesClient, service } = makeService();
      spacesClient.countBySpace.mockResolvedValueOnce({
        hits: { total: { value: 0 }, hits: [] },
      });

      await expect(service.countBySpace("alerts")).resolves.toEqual({
        kind: "alerts",
        days: 7,
        counts: {},
      });
    });
  });
});

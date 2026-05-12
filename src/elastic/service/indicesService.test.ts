/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { IndicesService } from "./indicesService.js";
import { createMockIndicesClient } from "../../test/helpers/mockServiceClients.js";

describe("IndicesService", () => {
  describe("listIndices", () => {
    it("uses the default pattern when none is supplied", async () => {
      const indicesClient = createMockIndicesClient();
      vi.mocked(indicesClient.catIndices).mockResolvedValueOnce([]);

      const service = new IndicesService({ indicesClient });
      await service.listIndices();

      expect(indicesClient.catIndices).toHaveBeenCalledWith(
        "logs-*,.alerts-security*",
        { format: "json", h: "index,health,status,docs.count,store.size", s: "index" }
      );
    });

    it("forwards the supplied pattern", async () => {
      const indicesClient = createMockIndicesClient();
      vi.mocked(indicesClient.catIndices).mockResolvedValueOnce([]);

      const service = new IndicesService({ indicesClient });
      await service.listIndices("custom-*");

      expect(indicesClient.catIndices).toHaveBeenCalledWith(
        "custom-*",
        { format: "json", h: "index,health,status,docs.count,store.size", s: "index" }
      );
    });

    it("normalises the cat-indices row shape into IndexInfo", async () => {
      const indicesClient = createMockIndicesClient();
      vi.mocked(indicesClient.catIndices).mockResolvedValueOnce([
        {
          index: "logs-1",
          health: "green",
          status: "open",
          "docs.count": "100",
          "store.size": "1mb",
        },
      ]);

      const service = new IndicesService({ indicesClient });
      const out = await service.listIndices();

      expect(out).toEqual([
        {
          index: "logs-1",
          health: "green",
          status: "open",
          docsCount: "100",
          storeSize: "1mb",
        },
      ]);
    });
  });

  describe("getMapping", () => {
    it("returns {} when the response envelope is empty", async () => {
      const indicesClient = createMockIndicesClient();
      vi.mocked(indicesClient.getRawMapping).mockResolvedValueOnce({});

      const service = new IndicesService({ indicesClient });
      const out = await service.getMapping("missing-*");

      expect(out).toEqual({});
    });

    it("flattens nested properties into dot-notation, preserving multi-fields", async () => {
      const indicesClient = createMockIndicesClient();
      vi.mocked(indicesClient.getRawMapping).mockResolvedValueOnce({
        "logs-x-default": {
          mappings: {
            properties: {
              host: {
                properties: {
                  name: {
                    type: "keyword",
                    fields: { text: { type: "text" } },
                  },
                },
              },
              "@timestamp": { type: "date" },
              raw: {},
            },
          } as never,
        },
      });

      const service = new IndicesService({ indicesClient });
      const out = await service.getMapping("logs-x-*");

      expect(out).toEqual({
        "host.name": {
          type: "keyword",
          fields: { text: { type: "text" } },
        },
        "@timestamp": { type: "date" },
        raw: { type: "object" },
      });
    });
  });
});

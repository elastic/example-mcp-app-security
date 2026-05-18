/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerMigrationTools } from "./migration.js";
import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { createMockMigrationsService } from "../test/helpers/mockServices.js";
import type { MigrationsService } from "../elastic/service/index.js";

const RESOURCE_URI = "ui://migrate-rules/mcp-app.html";
const MIGRATION_ID = "m-1";
const RULE_ID = "r-1";

function setup() {
  const server = createMockMcpServer();
  const migrationsService = createMockMigrationsService();
  vi.spyOn(fs, "existsSync").mockReturnValue(false);
  vi.spyOn(fs, "readFileSync").mockReturnValue("<html>migration</html>");
  registerMigrationTools(server as unknown as McpServer, { migrationsService });
  return { server, migrationsService };
}

describe("registerMigrationTools", () => {
  let server: MockMcpServer;
  let migrationsService: MigrationsService;

  beforeEach(() => {
    ({ server, migrationsService } = setup());
  });

  // ── Registration ───────────────────────────────────────────────────────────

  it("registers all 11 tools and the HTML resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "migrate-rules",
        "list-migrations",
        "get-migration",
        "get-translated-rules",
        "start-translation",
        "stop-translation",
        "update-translated-rule",
        "get-resources",
        "upsert-resource",
        "install-rules",
        "get-stats",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  // ── migrate-rules (model-facing) ───────────────────────────────────────────

  describe("migrate-rules", () => {
    it("returns a compact migration list for the LLM to see", async () => {
      vi.mocked(migrationsService.listMigrations).mockResolvedValueOnce([
        {
          id: MIGRATION_ID,
          name: "Splunk prod",
          status: "ready",
          created_at: "2026-01-01T00:00:00Z",
          last_updated_at: "2026-01-01T00:00:00Z",
          rules: {
            total: 10, pending: 5, processing: 0, completed: 5, failed: 0,
            installable: 5, installed: 0, partially_translated: 0, untranslatable: 0,
          },
        },
      ]);

      const out = parseToolText<{ message: string; migrations: unknown[] }>(
        await server.tool("migrate-rules").callback({})
      );

      expect(out.message).toContain("workbench");
      expect(out.migrations).toHaveLength(1);
      expect(out.migrations[0]).toMatchObject({ id: MIGRATION_ID, name: "Splunk prod" });
    });
  });

  // ── list-migrations ────────────────────────────────────────────────────────

  describe("list-migrations", () => {
    it("delegates to migrationsService.listMigrations and returns the array", async () => {
      vi.mocked(migrationsService.listMigrations).mockResolvedValueOnce([]);

      const out = parseToolText<unknown[]>(
        await server.tool("list-migrations").callback({})
      );

      expect(migrationsService.listMigrations).toHaveBeenCalledTimes(1);
      expect(out).toEqual([]);
    });
  });

  // ── get-migration ──────────────────────────────────────────────────────────

  describe("get-migration", () => {
    it("calls getMigration with the provided ID", async () => {
      vi.mocked(migrationsService.getMigration).mockResolvedValueOnce({
        id: MIGRATION_ID,
        name: "test",
        status: "ready",
        created_at: "",
        last_updated_at: "",
        rules: {
          total: 0, pending: 0, processing: 0, completed: 0, failed: 0,
          installable: 0, installed: 0, partially_translated: 0, untranslatable: 0,
        },
      });

      await server.tool("get-migration").callback({ migrationId: MIGRATION_ID });

      expect(migrationsService.getMigration).toHaveBeenCalledWith(MIGRATION_ID);
    });
  });

  // ── get-translated-rules ───────────────────────────────────────────────────

  describe("get-translated-rules", () => {
    it("forwards pagination params to getTranslatedRules", async () => {
      vi.mocked(migrationsService.getTranslatedRules).mockResolvedValueOnce({
        data: [],
        total: 0,
      });

      await server.tool("get-translated-rules").callback({
        migrationId: MIGRATION_ID,
        vendor: "splunk",
        page: 2,
        perPage: 50,
        filter: "status:completed",
      });

      expect(migrationsService.getTranslatedRules).toHaveBeenCalledWith(
        MIGRATION_ID,
        { page: 2, perPage: 50, filter: "status:completed" }
      );
    });

    it("returns vendorNotSupported for a non-Splunk vendor", async () => {
      const out = parseToolText<{ error: string; vendor: string }>(
        await server.tool("get-translated-rules").callback({
          migrationId: MIGRATION_ID,
          vendor: "qradar",
        })
      );

      expect(out).toEqual({ error: "vendorNotSupported", vendor: "qradar" });
      expect(migrationsService.getTranslatedRules).not.toHaveBeenCalled();
    });
  });

  // ── start-translation ──────────────────────────────────────────────────────

  describe("start-translation", () => {
    it("calls startTranslation and returns { status: 'started' }", async () => {
      vi.mocked(migrationsService.startTranslation).mockResolvedValueOnce(undefined);

      const out = parseToolText<{ status: string }>(
        await server.tool("start-translation").callback({
          migrationId: MIGRATION_ID,
          vendor: "splunk",
        })
      );

      expect(migrationsService.startTranslation).toHaveBeenCalledWith(MIGRATION_ID);
      expect(out.status).toBe("started");
    });

    it("returns vendorNotSupported for sentinel-one", async () => {
      const out = parseToolText<{ error: string; vendor: string }>(
        await server.tool("start-translation").callback({
          migrationId: MIGRATION_ID,
          vendor: "sentinel-one",
        })
      );

      expect(out).toEqual({ error: "vendorNotSupported", vendor: "sentinel-one" });
      expect(migrationsService.startTranslation).not.toHaveBeenCalled();
    });
  });

  // ── stop-translation ───────────────────────────────────────────────────────

  describe("stop-translation", () => {
    it("calls stopTranslation and returns { status: 'stopped' }", async () => {
      vi.mocked(migrationsService.stopTranslation).mockResolvedValueOnce(undefined);

      const out = parseToolText<{ status: string }>(
        await server.tool("stop-translation").callback({
          migrationId: MIGRATION_ID,
          vendor: "splunk",
        })
      );

      expect(migrationsService.stopTranslation).toHaveBeenCalledWith(MIGRATION_ID);
      expect(out.status).toBe("stopped");
    });

    it("returns vendorNotSupported for an unknown vendor", async () => {
      const out = parseToolText<{ error: string }>(
        await server.tool("stop-translation").callback({
          migrationId: MIGRATION_ID,
          vendor: "unknown-siem",
        })
      );

      expect(out.error).toBe("vendorNotSupported");
      expect(migrationsService.stopTranslation).not.toHaveBeenCalled();
    });
  });

  // ── update-translated-rule ─────────────────────────────────────────────────

  describe("update-translated-rule", () => {
    it("parses elasticRule JSON and passes updates to service", async () => {
      vi.mocked(migrationsService.updateTranslatedRule).mockResolvedValueOnce({
        id: RULE_ID,
        migration_id: MIGRATION_ID,
        status: "completed",
        translation_result: "partial",
        original_rule: {},
      });
      const elasticRule = { name: "Fixed rule", type: "query" };

      await server.tool("update-translated-rule").callback({
        migrationId: MIGRATION_ID,
        ruleId: RULE_ID,
        vendor: "splunk",
        elasticRule: JSON.stringify(elasticRule),
        translationResult: "partial",
      });

      expect(migrationsService.updateTranslatedRule).toHaveBeenCalledWith(
        MIGRATION_ID,
        RULE_ID,
        expect.objectContaining({
          elastic_rule: elasticRule,
          translation_result: "partial",
        })
      );
    });

    it("returns vendorNotSupported without calling service", async () => {
      const out = parseToolText<{ error: string }>(
        await server.tool("update-translated-rule").callback({
          migrationId: MIGRATION_ID,
          ruleId: RULE_ID,
          vendor: "qradar",
        })
      );

      expect(out.error).toBe("vendorNotSupported");
      expect(migrationsService.updateTranslatedRule).not.toHaveBeenCalled();
    });
  });

  // ── get-resources ──────────────────────────────────────────────────────────

  describe("get-resources", () => {
    it("calls getResources with migrationId", async () => {
      vi.mocked(migrationsService.getResources).mockResolvedValueOnce([
        { type: "macro", name: "my_macro", content: "| where true" },
      ]);

      const out = parseToolText<unknown[]>(
        await server.tool("get-resources").callback({
          migrationId: MIGRATION_ID,
          vendor: "splunk",
        })
      );

      expect(migrationsService.getResources).toHaveBeenCalledWith(MIGRATION_ID);
      expect(out).toHaveLength(1);
    });

    it("returns vendorNotSupported for non-Splunk", async () => {
      const out = parseToolText<{ error: string }>(
        await server.tool("get-resources").callback({
          migrationId: MIGRATION_ID,
          vendor: "qradar",
        })
      );

      expect(out.error).toBe("vendorNotSupported");
    });
  });

  // ── upsert-resource ────────────────────────────────────────────────────────

  describe("upsert-resource", () => {
    it("calls upsertResources with a single-element array", async () => {
      vi.mocked(migrationsService.upsertResources).mockResolvedValueOnce(undefined);

      await server.tool("upsert-resource").callback({
        migrationId: MIGRATION_ID,
        vendor: "splunk",
        type: "macro",
        name: "splunk_macro",
        content: "| eval x=1",
      });

      expect(migrationsService.upsertResources).toHaveBeenCalledWith(
        MIGRATION_ID,
        [{ type: "macro", name: "splunk_macro", content: "| eval x=1" }]
      );
    });

    it("returns vendorNotSupported for non-Splunk", async () => {
      const out = parseToolText<{ error: string }>(
        await server.tool("upsert-resource").callback({
          migrationId: MIGRATION_ID,
          vendor: "sentinel-one",
          type: "macro",
          name: "m",
          content: "",
        })
      );

      expect(out.error).toBe("vendorNotSupported");
      expect(migrationsService.upsertResources).not.toHaveBeenCalled();
    });
  });

  // ── install-rules ──────────────────────────────────────────────────────────

  describe("install-rules", () => {
    it("passes ids array to installRules", async () => {
      vi.mocked(migrationsService.installRules).mockResolvedValueOnce({
        installed: 2,
        failed: 0,
      });

      const out = parseToolText<{ installed: number; failed: number }>(
        await server.tool("install-rules").callback({
          migrationId: MIGRATION_ID,
          vendor: "splunk",
          ids: ["r-1", "r-2"],
        })
      );

      expect(migrationsService.installRules).toHaveBeenCalledWith(
        MIGRATION_ID,
        { ids: ["r-1", "r-2"] }
      );
      expect(out).toEqual({ installed: 2, failed: 0 });
    });

    it("returns vendorNotSupported for non-Splunk", async () => {
      const out = parseToolText<{ error: string }>(
        await server.tool("install-rules").callback({
          migrationId: MIGRATION_ID,
          vendor: "qradar",
        })
      );

      expect(out.error).toBe("vendorNotSupported");
      expect(migrationsService.installRules).not.toHaveBeenCalled();
    });
  });

  // ── get-stats ──────────────────────────────────────────────────────────────

  describe("get-stats", () => {
    it("calls getStats and returns the result (no vendor gate)", async () => {
      const stats = {
        id: MIGRATION_ID,
        status: "ready" as const,
        rules: {
          total: 5, pending: 5, processing: 0, completed: 0, failed: 0,
          installable: 0, installed: 0, partially_translated: 0, untranslatable: 0,
        },
      };
      vi.mocked(migrationsService.getStats).mockResolvedValueOnce(stats);

      const out = parseToolText<typeof stats>(
        await server.tool("get-stats").callback({ migrationId: MIGRATION_ID })
      );

      expect(migrationsService.getStats).toHaveBeenCalledWith(MIGRATION_ID);
      expect(out).toEqual(stats);
    });
  });

  // ── Vendor gate: undefined vendor is allowed ───────────────────────────────

  it("proceeds when vendor parameter is absent (defaults to Splunk path)", async () => {
    vi.mocked(migrationsService.startTranslation).mockResolvedValueOnce(undefined);

    const out = parseToolText<{ status: string }>(
      await server.tool("start-translation").callback({ migrationId: MIGRATION_ID })
    );

    expect(out.status).toBe("started");
    expect(migrationsService.startTranslation).toHaveBeenCalled();
  });
});

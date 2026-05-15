/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  MigrationsService,
  MigrationApiError,
  SIEM_MIGRATIONS_API_BASE,
} from "./migrationsService.js";
import type { KibanaClient } from "../kibana-client/index.js";
import {
  createMockKibanaClient,
  dataEnvelope,
  type MockHttpClient,
} from "../../test/helpers/mockHttpClient.js";
import type { SiemMigration, TranslatedRule, MigrationResource } from "./migrationsService.js";

const BASE = SIEM_MIGRATIONS_API_BASE;
const HEADERS = { headers: { "elastic-api-version": "2023-10-31" } };

const MIGRATION_ID = "migration-1";
const RULE_ID = "rule-1";

const fakeMigration: SiemMigration = {
  id: MIGRATION_ID,
  name: "test-migration",
  status: "ready",
  created_at: "2026-01-01T00:00:00Z",
  last_updated_at: "2026-01-01T00:00:00Z",
  rules: {
    total: 0, pending: 0, processing: 0, completed: 0, failed: 0,
    installable: 0, installed: 0, partially_translated: 0, untranslatable: 0,
  },
};

const fakeRule: TranslatedRule = {
  id: RULE_ID,
  migration_id: MIGRATION_ID,
  status: "completed",
  translation_result: "full",
  original_rule: { name: "splunk-rule" },
};

const fakeResource: MigrationResource = {
  type: "macro",
  name: "my_macro",
  content: "| where true",
};

describe("MigrationsService", () => {
  let kibanaClient: KibanaClient & MockHttpClient;
  let service: MigrationsService;

  beforeEach(() => {
    kibanaClient = createMockKibanaClient();
    service = new MigrationsService({ kibanaClient });
  });

  // ── Migration lifecycle ────────────────────────────────────────────────────

  describe("createMigration", () => {
    it("POSTs to /rules with the migration name and returns migration_id", async () => {
      kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ migration_id: MIGRATION_ID }));

      const result = await service.createMigration("My Migration");

      expect(kibanaClient.post).toHaveBeenCalledWith(
        `${BASE}/rules`,
        { name: "My Migration" },
        HEADERS
      );
      expect(result).toEqual({ migration_id: MIGRATION_ID });
    });
  });

  describe("listMigrations", () => {
    it("GETs /rules and returns the array", async () => {
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope([fakeMigration]));

      const result = await service.listMigrations();

      expect(kibanaClient.get).toHaveBeenCalledWith(`${BASE}/rules`, HEADERS);
      expect(result).toEqual([fakeMigration]);
    });
  });

  describe("getMigration", () => {
    it("GETs /rules/:migrationId and returns the migration", async () => {
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope(fakeMigration));

      const result = await service.getMigration(MIGRATION_ID);

      expect(kibanaClient.get).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}`,
        HEADERS
      );
      expect(result).toEqual(fakeMigration);
    });
  });

  describe("deleteMigration", () => {
    it("DELETEs /rules/:migrationId", async () => {
      await service.deleteMigration(MIGRATION_ID);

      expect(kibanaClient.delete).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}`,
        HEADERS
      );
    });
  });

  // ── Rule upload ────────────────────────────────────────────────────────────

  describe("uploadRules", () => {
    it("POSTs rules array to /rules/:migrationId/rules and returns totals", async () => {
      kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ total: 5 }));
      const splunkRules = [{ search: "index=main" }, { search: "index=security" }];

      const result = await service.uploadRules(MIGRATION_ID, splunkRules);

      expect(kibanaClient.post).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/rules`,
        splunkRules,
        HEADERS
      );
      expect(result).toEqual({ total: 5 });
    });
  });

  // ── Translated rules ───────────────────────────────────────────────────────

  describe("getTranslatedRules", () => {
    it("GETs /rules/:migrationId/rules with default pagination", async () => {
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ data: [fakeRule], total: 1 }));

      const result = await service.getTranslatedRules(MIGRATION_ID);

      const [path, config] = kibanaClient.get.mock.calls[0] as [string, Record<string, unknown>];
      expect(path).toBe(`${BASE}/rules/${MIGRATION_ID}/rules`);
      expect(config.params).toMatchObject({ page: "1", per_page: "20" });
      expect(result).toEqual({ data: [fakeRule], total: 1 });
    });

    it("forwards custom page, perPage and filter params", async () => {
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ data: [], total: 0 }));

      await service.getTranslatedRules(MIGRATION_ID, { page: 2, perPage: 50, filter: "status:completed" });

      const [, config] = kibanaClient.get.mock.calls[0] as [string, Record<string, unknown>];
      expect(config.params).toEqual({ page: "2", per_page: "50", filter: "status:completed" });
    });
  });

  describe("getTranslatedRule", () => {
    it("GETs /rules/:migrationId/rules/:ruleId", async () => {
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope(fakeRule));

      const result = await service.getTranslatedRule(MIGRATION_ID, RULE_ID);

      expect(kibanaClient.get).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/rules/${RULE_ID}`,
        HEADERS
      );
      expect(result).toEqual(fakeRule);
    });
  });

  describe("updateTranslatedRule", () => {
    it("PUTs updates to /rules/:migrationId/rules/:ruleId and returns the updated rule", async () => {
      const updated = { ...fakeRule, translation_result: "partial" as const };
      kibanaClient.put.mockResolvedValueOnce(dataEnvelope(updated));

      const result = await service.updateTranslatedRule(MIGRATION_ID, RULE_ID, {
        translation_result: "partial",
      });

      expect(kibanaClient.put).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/rules/${RULE_ID}`,
        { translation_result: "partial" },
        HEADERS
      );
      expect(result).toEqual(updated);
    });
  });

  // ── Translation control ────────────────────────────────────────────────────

  describe("startTranslation", () => {
    it("POSTs to /rules/:migrationId/start", async () => {
      await service.startTranslation(MIGRATION_ID);

      expect(kibanaClient.post).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/start`,
        {},
        HEADERS
      );
    });
  });

  describe("stopTranslation", () => {
    it("POSTs to /rules/:migrationId/stop", async () => {
      await service.stopTranslation(MIGRATION_ID);

      expect(kibanaClient.post).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/stop`,
        {},
        HEADERS
      );
    });
  });

  // ── Resources ──────────────────────────────────────────────────────────────

  describe("getResources", () => {
    it("GETs /resources/:migrationId and returns the array", async () => {
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope([fakeResource]));

      const result = await service.getResources(MIGRATION_ID);

      expect(kibanaClient.get).toHaveBeenCalledWith(
        `${BASE}/resources/${MIGRATION_ID}`,
        HEADERS
      );
      expect(result).toEqual([fakeResource]);
    });
  });

  describe("upsertResources", () => {
    it("POSTs resources array to /resources/:migrationId", async () => {
      await service.upsertResources(MIGRATION_ID, [fakeResource]);

      expect(kibanaClient.post).toHaveBeenCalledWith(
        `${BASE}/resources/${MIGRATION_ID}`,
        [fakeResource],
        HEADERS
      );
    });
  });

  // ── Installation ───────────────────────────────────────────────────────────

  describe("installRules", () => {
    it("POSTs empty body to /rules/:migrationId/install when no ids given", async () => {
      kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ installed: 3, failed: 0 }));

      const result = await service.installRules(MIGRATION_ID);

      expect(kibanaClient.post).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/install`,
        {},
        HEADERS
      );
      expect(result).toEqual({ installed: 3, failed: 0 });
    });

    it("includes ids in the body when provided", async () => {
      kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ installed: 1, failed: 0 }));

      await service.installRules(MIGRATION_ID, { ids: ["r1", "r2"] });

      const [, body] = kibanaClient.post.mock.calls[0] as [string, Record<string, unknown>];
      expect(body).toEqual({ ids: ["r1", "r2"] });
    });
  });

  // ── Stats ──────────────────────────────────────────────────────────────────

  describe("getStats", () => {
    it("GETs /rules/:migrationId/stats and returns the stats", async () => {
      const stats = { id: MIGRATION_ID, status: "ready" as const, rules: fakeMigration.rules };
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope(stats));

      const result = await service.getStats(MIGRATION_ID);

      expect(kibanaClient.get).toHaveBeenCalledWith(
        `${BASE}/rules/${MIGRATION_ID}/stats`,
        HEADERS
      );
      expect(result).toEqual(stats);
    });
  });

  // ── MigrationApiError ──────────────────────────────────────────────────────

  describe("MigrationApiError", () => {
    it("wraps non-2xx with status parsed from Kibana error format", async () => {
      const path = `${BASE}/rules/${MIGRATION_ID}`;
      kibanaClient.get.mockRejectedValue(
        new Error("Kibana [test-cluster] 404: migration not found")
      );

      await expect(service.getMigration(MIGRATION_ID)).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.getMigration(MIGRATION_ID)).rejects.toMatchObject({
        status: 404,
        path,
        message: expect.stringContaining(path) as string,
      });
    });

    it("sets status 0 when error message has no HTTP status code", async () => {
      kibanaClient.get.mockRejectedValueOnce(new Error("network timeout"));

      const err = await service.getMigration(MIGRATION_ID).catch((e) => e as MigrationApiError);
      expect(err).toBeInstanceOf(MigrationApiError);
      expect(err.status).toBe(0);
    });

    it("surfaces a MigrationApiError from every mutating method", async () => {
      const netErr = new Error("Kibana [test-cluster] 503: service unavailable");

      kibanaClient.post.mockRejectedValue(netErr);
      kibanaClient.put.mockRejectedValue(netErr);
      kibanaClient.delete.mockRejectedValue(netErr);

      await expect(service.createMigration("x")).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.uploadRules(MIGRATION_ID, [])).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.startTranslation(MIGRATION_ID)).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.stopTranslation(MIGRATION_ID)).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.upsertResources(MIGRATION_ID, [])).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.installRules(MIGRATION_ID)).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.updateTranslatedRule(MIGRATION_ID, RULE_ID, {})).rejects.toBeInstanceOf(MigrationApiError);
      await expect(service.deleteMigration(MIGRATION_ID)).rejects.toBeInstanceOf(MigrationApiError);
    });
  });
});

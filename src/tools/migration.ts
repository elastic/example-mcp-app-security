/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import type { MigrationsService } from "../elastic/service/index.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://migrate-rules/mcp-app.html";

/**
 * Vendors for which the Kibana SIEM migrations translator is production-ready.
 * Re-enabling a vendor is a one-line change to this array once the translator
 * matures — QRadar and Sentinel-One are the next candidates.
 */
const SUPPORTED_VENDORS: readonly string[] = ["splunk"];

export interface MigrationToolDeps {
  readonly migrationsService: MigrationsService;
}

/** Returns a vendor-gate error response for app-only tools. */
function vendorNotSupportedResponse(vendor: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({ error: "vendorNotSupported", vendor }),
      },
    ],
  };
}

/** Returns true when `vendor` is explicitly provided but not in SUPPORTED_VENDORS. */
function isUnsupportedVendor(vendor: string | undefined): vendor is string {
  return vendor !== undefined && !SUPPORTED_VENDORS.includes(vendor);
}

export function registerMigrationTools(
  server: McpServer,
  deps: MigrationToolDeps
) {
  const { migrationsService } = deps;

  // ── Model-facing entry-point ───────────────────────────────────────────────

  registerAppTool(
    server,
    "migrate-rules",
    {
      title: "Migrate Rules",
      description:
        "Migrate detection rules from Splunk (and other SIEMs) to Elastic Security. " +
        "Opens an interactive migration workbench for uploading, translating, reviewing, " +
        "and installing rules. Vendor support: Splunk (active), QRadar / Sentinel-One (coming soon).",
      inputSchema: {},
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async () => {
      const migrations = await migrationsService.listMigrations();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              message: "Opening SIEM migration workbench",
              migrations: migrations.map(({ id, name, status }) => ({ id, name, status })),
            }),
          },
        ],
      };
    }
  );

  // ── App-only tools ─────────────────────────────────────────────────────────

  registerAppTool(
    server,
    "list-migrations",
    {
      title: "List Migrations",
      description: "List all SIEM rule migrations.",
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      const migrations = await migrationsService.listMigrations();
      return {
        content: [{ type: "text" as const, text: JSON.stringify(migrations) }],
      };
    }
  );

  registerAppTool(
    server,
    "get-migration",
    {
      title: "Get Migration",
      description: "Get details for a specific SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId }) => {
      const migration = await migrationsService.getMigration(migrationId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(migration) }],
      };
    }
  );

  registerAppTool(
    server,
    "get-translated-rules",
    {
      title: "Get Translated Rules",
      description: "Get translated rules for a SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
        page: z.number().optional(),
        perPage: z.number().optional(),
        filter: z.string().optional(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, vendor, page, perPage, filter }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      const result = await migrationsService.getTranslatedRules(migrationId, {
        page,
        perPage,
        filter,
      });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  registerAppTool(
    server,
    "start-translation",
    {
      title: "Start Translation",
      description: "Start the AI translation process for a SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, vendor }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      await migrationsService.startTranslation(migrationId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ status: "started" }) }],
      };
    }
  );

  registerAppTool(
    server,
    "stop-translation",
    {
      title: "Stop Translation",
      description: "Stop the AI translation process for a SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, vendor }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      await migrationsService.stopTranslation(migrationId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ status: "stopped" }) }],
      };
    }
  );

  registerAppTool(
    server,
    "update-translated-rule",
    {
      title: "Update Translated Rule",
      description: "Update a translated rule in a SIEM migration (e.g. fix its Elastic rule JSON).",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        ruleId: z.string().describe("Translated rule ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
        elasticRule: z
          .string()
          .optional()
          .describe("JSON-encoded Elastic rule updates"),
        translationResult: z
          .enum(["full", "partial", "untranslatable"])
          .optional(),
        comments: z.array(z.string()).optional(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, ruleId, vendor, elasticRule, translationResult, comments }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      const updates: Record<string, unknown> = {};
      if (elasticRule !== undefined)
        updates.elastic_rule = JSON.parse(elasticRule) as Record<string, unknown>;
      if (translationResult !== undefined) updates.translation_result = translationResult;
      if (comments !== undefined) updates.comments = comments;
      const result = await migrationsService.updateTranslatedRule(migrationId, ruleId, updates);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  registerAppTool(
    server,
    "get-resources",
    {
      title: "Get Resources",
      description: "Get macro/lookup resources for a SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, vendor }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      const resources = await migrationsService.getResources(migrationId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(resources) }],
      };
    }
  );

  registerAppTool(
    server,
    "upsert-resource",
    {
      title: "Upsert Resource",
      description: "Create or update a macro/lookup resource in a SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
        type: z.enum(["macro", "lookup"]).describe("Resource type"),
        name: z.string().describe("Resource name"),
        content: z.string().describe("Resource content"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, vendor, type, name, content }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      await migrationsService.upsertResources(migrationId, [{ type, name, content }]);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ status: "ok" }) }],
      };
    }
  );

  registerAppTool(
    server,
    "install-rules",
    {
      title: "Install Rules",
      description: "Install translated rules from a SIEM migration into Elastic Security.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
        vendor: z
          .string()
          .optional()
          .describe("Source vendor (e.g. 'splunk'). Non-Splunk returns an error."),
        ids: z
          .array(z.string())
          .optional()
          .describe("Specific rule IDs to install. Omit to install all installable rules."),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId, vendor, ids }) => {
      if (isUnsupportedVendor(vendor)) return vendorNotSupportedResponse(vendor);
      const result = await migrationsService.installRules(migrationId, { ids });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  registerAppTool(
    server,
    "get-stats",
    {
      title: "Get Stats",
      description: "Get translation and installation statistics for a SIEM migration.",
      inputSchema: {
        migrationId: z.string().describe("Migration ID"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ migrationId }) => {
      const stats = await migrationsService.getStats(migrationId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(stats) }],
      };
    }
  );

  // ── App resource (HTML workbench) ──────────────────────────────────────────

  const viewPath = resolveViewPath("migration");
  registerAppResource(
    server,
    RESOURCE_URI,
    RESOURCE_URI,
    { mimeType: RESOURCE_MIME_TYPE },
    async () => {
      const html = fs.readFileSync(viewPath, "utf-8");
      return {
        contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }],
      };
    }
  );
}

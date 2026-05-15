/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAlertTriageTools } from "../../src/tools/alert-triage.js";
import { registerAttackDiscoveryTools } from "../../src/tools/attack-discovery.js";
import { registerCaseManagementTools } from "../../src/tools/case-management.js";
import { registerDetectionRuleTools } from "../../src/tools/detection-rules.js";
import { registerMigrationTools } from "../../src/tools/migration.js";
import { registerSampleDataTools } from "../../src/tools/sample-data.js";
import { registerThreatHuntTools } from "../../src/tools/threat-hunt.js";
import type { AlertsService } from "../../src/elastic/service/alertsService.js";
import type { AttackDiscoveryService } from "../../src/elastic/service/attackDiscoveryService.js";
import type { CasesService } from "../../src/elastic/service/casesService.js";
import type { EntityDetailService } from "../../src/elastic/service/entityDetailService.js";
import type { EsqlService } from "../../src/elastic/service/esqlService.js";
import type { IndicesService } from "../../src/elastic/service/indicesService.js";
import type { InvestigateService } from "../../src/elastic/service/investigateService.js";
import type { MigrationsService } from "../../src/elastic/service/migrationsService.js";
import type { RulesService } from "../../src/elastic/service/rulesService.js";
import type { SampleDataService } from "../../src/elastic/service/sampleDataService.js";

/**
 * Stubs every service used by the seven tool groups registered on the live
 * MCP server. Methods invoked by model-facing entry tools resolve to
 * realistic-shaped empty payloads; other methods are bare `vi.fn()` because
 * skill-routing evaluators only inspect which tools the LLM called, not
 * what those tools returned.
 *
 * Mirrors `src/server.ts` exactly: the LLM that drives the eval host loop
 * must see the same tool surface a real MCP host (Claude Desktop, Cursor)
 * exposes — otherwise we measure skill-selection against an artificially
 * narrow distractor set and over-state activation rates for small models.
 */
export function createEvalServer(): McpServer {
  const server = new McpServer({ name: "eval-server", version: "0.0.0" });

  const alertsService = {
    searchAlerts: vi.fn().mockResolvedValue({ alerts: [], total: 0 }),
    findAlertById: vi.fn().mockResolvedValue(null),
  } as unknown as AlertsService;

  const attackDiscoveryService = {
    listAttackDiscoveries: vi.fn().mockResolvedValue([]),
  } as unknown as AttackDiscoveryService;

  const casesService = {
    findCases: vi.fn().mockResolvedValue({ cases: [], total: 0 }),
  } as unknown as CasesService;

  const entityDetailService = {
    getEntityDetail: vi.fn().mockResolvedValue(null),
  } as unknown as EntityDetailService;

  const esqlService = {
    executeQuery: vi.fn().mockResolvedValue({ columns: [], values: [] }),
  } as unknown as EsqlService;

  const indicesService = {
    listIndices: vi.fn().mockResolvedValue([]),
  } as unknown as IndicesService;

  const investigateService = {
    getRelatedAlerts: vi.fn().mockResolvedValue([]),
  } as unknown as InvestigateService;

  const migrationsService = {
    listMigrations: vi.fn().mockResolvedValue([]),
  } as unknown as MigrationsService;

  const rulesService = {
    findRules: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  } as unknown as RulesService;

  const sampleDataService = {
    listScenarios: vi.fn().mockResolvedValue([]),
  } as unknown as SampleDataService;

  registerAlertTriageTools(server, { alertsService });
  registerAttackDiscoveryTools(server, { attackDiscoveryService, casesService });
  registerCaseManagementTools(server, { casesService });
  registerDetectionRuleTools(server, { rulesService });
  registerMigrationTools(server, { migrationsService });
  registerSampleDataTools(server, { sampleDataService });
  registerThreatHuntTools(server, {
    esqlService,
    indicesService,
    investigateService,
    entityDetailService,
  });

  return server;
}

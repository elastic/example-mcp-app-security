/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi } from "vitest";
import type { AlertsService } from "../../elastic/service/alertsService.js";
import type { AttackDiscoveryService } from "../../elastic/service/attackDiscoveryService.js";
import type { CasesService } from "../../elastic/service/casesService.js";
import type { EntityDetailService } from "../../elastic/service/entityDetailService.js";
import type { EsqlService } from "../../elastic/service/esqlService.js";
import type { IndicesService } from "../../elastic/service/indicesService.js";
import type { InvestigateService } from "../../elastic/service/investigateService.js";
import type { RulesService } from "../../elastic/service/rulesService.js";
import type { SampleDataService } from "../../elastic/service/sampleDataService.js";
import type { SpacesService } from "../../elastic/service/spacesService.js";

/**
 * Build a mocked service where every named method is a `vi.fn()`. The
 * returned object is typed as `T` so tests get full IntelliSense without
 * intermediate casts. Callers configure individual methods via
 * `vi.mocked(service.someMethod).mockResolvedValueOnce(...)`.
 */
function mockService<T extends object>(methodNames: readonly (keyof T)[]): T {
  const mock = {} as Record<keyof T, ReturnType<typeof vi.fn>>;
  for (const name of methodNames) {
    mock[name] = vi.fn();
  }
  return mock as unknown as T;
}

export function createMockAlertsService(): AlertsService {
  return mockService<AlertsService>([
    "getAlerts",
    "getAlertContext",
    "acknowledgeAlert",
    "acknowledgeAlerts",
  ]);
}

export function createMockAttackDiscoveryService(): AttackDiscoveryService {
  return mockService<AttackDiscoveryService>([
    "getDiscoveries",
    "assessConfidence",
    "getDiscoveryDetail",
    "acknowledgeDiscoveries",
    "generateAttackDiscovery",
    "getGenerations",
    "listAIConnectors",
  ]);
}

export function createMockCasesService(): CasesService {
  return mockService<CasesService>([
    "listCases",
    "getCase",
    "createCase",
    "updateCase",
    "addComment",
    "attachAlert",
    "attachAlertsByIds",
    "getCasesForAlert",
    "getComments",
    "getUserProfile",
    "getCaseAlerts",
  ]);
}

export function createMockEntityDetailService(): EntityDetailService {
  return mockService<EntityDetailService>(["getEntityDetail"]);
}

export function createMockEsqlService(): EsqlService {
  return mockService<EsqlService>(["executeEsql"]);
}

export function createMockIndicesService(): IndicesService {
  return mockService<IndicesService>(["listIndices", "getMapping"]);
}

export function createMockInvestigateService(): InvestigateService {
  return mockService<InvestigateService>(["investigateEntity"]);
}

export function createMockRulesService(): RulesService {
  return mockService<RulesService>([
    "findRules",
    "getRule",
    "createRule",
    "patchRule",
    "deleteRule",
    "toggleRule",
    "bulkAction",
    "addException",
    "listExceptions",
    "validateQuery",
    "noisyRules",
  ]);
}

export function createMockSampleDataService(): SampleDataService {
  return mockService<SampleDataService>([
    "generateSampleData",
    "cleanupSampleData",
    "checkExistingData",
    "createRulesForScenario",
    "setRuleIdMap",
  ]);
}

export function createMockSpacesService(): SpacesService {
  return mockService<SpacesService>(["listSpaces"]);
}

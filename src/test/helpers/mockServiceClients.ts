/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi } from "vitest";
import type { AlertsClient } from "../../elastic/client/alertsClient.js";
import type { AttackDiscoveryClient } from "../../elastic/client/attackDiscoveryClient.js";
import type { CasesClient } from "../../elastic/client/casesClient.js";
import type { EntityDetailClient } from "../../elastic/client/entityDetailClient.js";
import type { EsqlClient } from "../../elastic/client/esqlClient.js";
import type { IndicesClient } from "../../elastic/client/indicesClient.js";
import type { InvestigateClient } from "../../elastic/client/investigateClient.js";
import type { RulesClient } from "../../elastic/client/rulesClient.js";
import type { SampleDataClient } from "../../elastic/client/sampleDataClient.js";
import type { RulesService } from "../../elastic/service/rulesService.js";

/**
 * Builds a mocked client where every public method is a `vi.fn()` resolved
 * to `undefined`. We type it as `T` so call sites get full IntelliSense
 * without intermediate casts.
 */
function mockClient<T extends object>(methodNames: readonly (keyof T)[]): T {
  const mock = {} as Record<keyof T, ReturnType<typeof vi.fn>>;
  for (const name of methodNames) {
    mock[name] = vi.fn();
  }
  return mock as unknown as T;
}

export function createMockAlertsClient(): AlertsClient {
  return mockClient<AlertsClient>([
    "searchAlerts",
    "searchProcessEvents",
    "searchNetworkEvents",
    "updateAlert",
    "updateAlertsByQuery",
  ]);
}

export function createMockAttackDiscoveryClient(): AttackDiscoveryClient {
  return mockClient<AttackDiscoveryClient>([
    "runEsql",
    "acknowledgeOnIndex",
    "generate",
    "listConnectors",
    "findAnonymizationFields",
    "getGenerations",
  ]);
}

export function createMockCasesClient(): CasesClient {
  return mockClient<CasesClient>([
    "findCases",
    "getCase",
    "createCase",
    "updateCases",
    "addComment",
    "getCaseAlerts",
    "getCommentsFind",
    "getCasesForAlert",
    "getUserProfile",
    "getAlertDocument",
    "mgetAlerts",
  ]);
}

export function createMockEntityDetailClient(): EntityDetailClient {
  return mockClient<EntityDetailClient>(["searchByTerms"]);
}

export function createMockEsqlClient(): EsqlClient {
  return mockClient<EsqlClient>(["executeEsql"]);
}

export function createMockIndicesClient(): IndicesClient {
  return mockClient<IndicesClient>(["catIndices", "getRawMapping"]);
}

export function createMockInvestigateClient(): InvestigateClient {
  return mockClient<InvestigateClient>(["runEsql"]);
}

export function createMockRulesClient(): RulesClient {
  return mockClient<RulesClient>([
    "findRules",
    "getRule",
    "createRule",
    "patchRule",
    "deleteRule",
    "bulkAction",
    "addException",
    "listExceptions",
    "validateEsql",
    "validateKqlOrEql",
    "searchAlertsAggregation",
  ]);
}

export function createMockSampleDataClient(): SampleDataClient {
  return mockClient<SampleDataClient>([
    "bulkIndex",
    "deleteByQuery",
    "count",
    "searchAlertsAggregation",
  ]);
}

export function createMockRulesService(): RulesService {
  return mockClient<RulesService>([
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

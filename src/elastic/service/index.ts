/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export { AlertsService } from "./alertsService.js";
export { EsqlService } from "./esqlService.js";
export { IndicesService } from "./indicesService.js";
export { EntityDetailService } from "./entityDetailService.js";
export { InvestigateService } from "./investigateService.js";
export { RulesService } from "./rulesService.js";
export type { CaseAlertAttachment } from "./casesService.js";
export { CasesService } from "./casesService.js";
export { AttackDiscoveryService } from "./attackDiscoveryService.js";
export type {
  ScenarioName,
  ScenarioRuleDef,
} from "./sampleDataService.js";
export { SampleDataService, SCENARIO_NAMES, SCENARIO_RULES } from "./sampleDataService.js";
export { TelemetryService } from "./telemetryService.js";
export { CorrelationService } from "./correlationService.js";
export type {
  DiamondSearchParams,
  DiamondSearchResult,
  ReportStub,
  ReportFull,
  ScoredStub,
  DiamondSearchScoredResult,
  CoverageSignal,
  VertexScores,
} from "./correlationService.js";

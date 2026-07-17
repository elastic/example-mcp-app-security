/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export type {
  AlertSearchAggs,
  AlertSearchResponse,
  EsRequestBody,
  NetworkEventSearchResponse,
  ProcessEventSearchResponse,
  SearchResponse,
  TermBucket,
  UpdateByQueryResponse,
} from "./alertsClient.js";
export { AlertsClient } from "./alertsClient.js";

export { EsqlClient } from "./esqlClient.js";

export type {
  CatDocCountRow,
  CatIndexRow,
  InstalledPackage,
  RawActionConnector,
  RawDataStream,
  RawDataStreamStat,
  RawPackagePolicy,
} from "./environmentClient.js";
export { EnvironmentClient } from "./environmentClient.js";

export type { CatIndicesRow, RawMappingResponse } from "./indicesClient.js";
export { IndicesClient } from "./indicesClient.js";

export type { EntityDetail } from "./entityDetailClient.js";
export { EntityDetailClient } from "./entityDetailClient.js";

export type {
  EsqlEnvelope,
  GraphEdge,
  GraphNode,
  InvestigationResult,
} from "./investigateClient.js";
export { InvestigateClient } from "./investigateClient.js";

export type {
  FindResponse,
  NoisyRulesAggResponse,
  NoisyRulesBucket,
} from "./rulesClient.js";
export { RulesClient } from "./rulesClient.js";

export type {
  AlertSearchHit,
  CaseComment,
  FindCasesResponse,
  FindCommentsResponse,
  RawCaseAlert,
  SearchAlertsResponse,
  UserAvatar,
  UserProfileResponse,
} from "./casesClient.js";
export { CasesClient } from "./casesClient.js";

export type {
  AnonymizationField,
  AttackDiscovery,
  ConfidenceLevel,
  ConfidenceSignals,
  DiscoverySummary,
  GenerationResult,
  RawConnector,
  TriagedDiscovery,
} from "./attackDiscoveryClient.js";
export { AttackDiscoveryClient } from "./attackDiscoveryClient.js";

export type {
  AlertCheckResponse,
  AlertsByRuleBucket,
  BulkItemEnvelope,
  BulkResponse,
  CountResponse,
  DeleteByQueryResponse,
} from "./sampleDataClient.js";
export { SampleDataClient } from "./sampleDataClient.js";

export type { TelemetryConfig } from "./telemetryConfigClient.js";
export { TelemetryConfigClient } from "./telemetryConfigClient.js";

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export type {
  AnalyticsClient,
  ClusterContext,
  LicenseContext,
} from "./analytics-client.js";
export { noopAnalyticsClient } from "./analytics-client.js";
export type {
  McpToolCalledEbtPayload,
  ViewRenderedEbtPayload,
} from "./events.js";
export { EVENT_TYPES, VIEW_IDS, type ViewId } from "./events.js";
export {
  createAnalyticsClient,
  resolveTelemetrySendTo,
  type CreateAnalyticsClientOptions,
  type TelemetrySendTo,
} from "./create-analytics-client.js";
export {
  createContextLoader,
  type ContextLoader,
  type CreateContextLoaderDeps,
} from "./context-loader.js";

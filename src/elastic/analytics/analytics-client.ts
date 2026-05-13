/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { McpToolCalledEvent, ViewRenderedEvent } from "./events.js";

/**
 * Elasticsearch cluster context attached to outgoing telemetry events.
 *
 * `cluster_uuid` is required by the Elastic V3 shipper to build the
 * `x-elastic-cluster-id` header — events will not ship until at least
 * one `cluster_uuid` has been published into the analytics context.
 *
 * `cluster_name` is intentionally **not** shipped: it's user-controlled
 * and frequently contains company / environment identifiers that would
 * compromise the "anonymised" framing of this feed.
 */
export interface ClusterContext {
  readonly cluster_uuid: string;
  readonly cluster_version: string;
}

/** License context attached to outgoing telemetry events. All optional. */
export interface LicenseContext {
  readonly license_id?: string;
  readonly license_status?: string;
  readonly license_type?: string;
}

/**
 * MCP App's typed telemetry surface.
 *
 * Wraps `@elastic/ebt`'s `IAnalyticsClient` so the rest of the codebase
 * never touches EBT or RxJS directly. Each public method is typed
 * against the matching payload in `events.ts`, so a schema change there
 * is caught at compile time in every caller.
 *
 * The client always starts opted-out; call `setOptIn(true)` once the
 * Kibana telemetry config has been resolved (see `TelemetryService`).
 */
export interface AnalyticsClient {
  /** Report that an MCP tool handler resolved or threw. */
  trackToolCalled(event: McpToolCalledEvent): void;

  /** Report that a React view mounted. */
  trackViewRendered(event: ViewRenderedEvent): void;

  /**
   * Mirror the user's Kibana telemetry opt-in onto the EBT client.
   * `false` flushes and drops the in-memory queue immediately.
   */
  setOptIn(enabled: boolean): void;

  /**
   * Publish cluster context. Required for the `x-elastic-cluster-id`
   * header. Calling again replaces the previous value.
   */
  setClusterContext(ctx: ClusterContext): void;

  /** Publish license context. Calling again replaces the previous value. */
  setLicenseContext(ctx: LicenseContext): void;

  /** Flush any queued events and tear the shipper down. */
  shutdown(): Promise<void>;
}

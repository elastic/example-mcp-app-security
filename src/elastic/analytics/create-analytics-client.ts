/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createAnalytics } from "@elastic/ebt/client/index.js";
import type { AnalyticsClientInitContext } from "@elastic/ebt/client/index.js";
import { ElasticV3ServerShipper } from "@elastic/ebt/shippers/elastic_v3/server/index.js";
import { createStderrLogger, type Logger } from "../../shared/logger.js";

/**
 * EBT exports `AnalyticsClientInitContext` but not the `Logger` type
 * directly. Derive it from the public surface so we don't reach into
 * the package's internal paths.
 */
type EbtLogger = AnalyticsClientInitContext["logger"];
import { BehaviorSubject } from "rxjs";
import type { AnalyticsClient, ClusterContext, LicenseContext } from "./analytics-client.js";
import {
  EVENT_TYPES,
  mcpToolCalledEventDef,
  viewRenderedEventDef,
  type McpToolCalledEbtPayload,
  type ViewRenderedEbtPayload,
} from "./events.js";

const CHANNEL_NAME = "elastic-security-mcp-app";
const noop = (): void => undefined;
export type TelemetrySendTo = "production" | "staging";

const defaultLogger = createStderrLogger(["telemetry"]);
const defaultLoggerBase: Pick<Logger, "info" | "warn" | "error" | "debug"> = {
  debug: noop,
  info: (msg) => defaultLogger.info(msg),
  warn: (msg) => defaultLogger.warn(msg),
  error: (msg) => defaultLogger.error(msg),
};

/**
 * The base URL of the V3 telemetry endpoint, selected from
 * `MCP_APP_TELEMETRY_ENV`. Defaults to production for end-user
 * installs (`.mcpb` ships without the env var set).
 */
export function resolveTelemetrySendTo(env: string | undefined): TelemetrySendTo {
  return env === "staging" ? "staging" : "production";
}

function baseUrlFor(sendTo: TelemetrySendTo): string {
  return sendTo === "production"
    ? "https://telemetry.elastic.co"
    : "https://telemetry-staging.elastic.co";
}

function logReportedEvent(
  logger: Pick<EbtLogger, "info">,
  sendTo: TelemetrySendTo,
  eventType: string,
  event: McpToolCalledEbtPayload | ViewRenderedEbtPayload,
): void {
  logger.info(
    `reported event: send_to=${sendTo} type=${eventType} payload=${JSON.stringify(event)}`,
  );
}

/**
 * Adapts a `Console`-shaped logger to EBT's `Logger` interface
 * (which requires `.get(...)` to return a child logger). We don't
 * use the EBT debug logging for anything more than visibility into
 * shipper internals during local dev, so a no-op child is fine.
 */
function adaptLogger(
  base: Pick<Logger, "info" | "warn" | "error" | "debug">,
): EbtLogger {
  const logger: EbtLogger = {
    debug: (msg) => base.debug(typeof msg === "function" ? msg() : msg),
    info: (msg) => base.info(typeof msg === "function" ? msg() : msg),
    warn: (msg) => {
      if (msg instanceof Error) base.warn(msg);
      else base.warn(typeof msg === "function" ? msg() : msg);
    },
    error: (msg) => {
      if (msg instanceof Error) base.error(msg);
      else base.error(typeof msg === "function" ? msg() : msg);
    },
    get: () => logger,
  };
  return logger;
}

export interface CreateAnalyticsClientOptions {
  readonly mcpAppVersion: string;
  readonly sendTo?: TelemetrySendTo;
  readonly logger?: Pick<Logger, "info" | "warn" | "error" | "debug">;
}

/**
 * Build a {@link AnalyticsClient} backed by `@elastic/ebt`.
 *
 * The client is constructed opted-out — `setOptIn(true)` must be
 * called explicitly (via `TelemetryService.applyOptIn()`) once the
 * user's Kibana telemetry opt-in has been resolved.
 *
 * Encapsulates everything EBT/RxJS-shaped so nothing outside this
 * module needs to import either.
 */
export function createAnalyticsClient(
  opts: CreateAnalyticsClientOptions,
): AnalyticsClient {
  const sendTo = opts.sendTo ?? resolveTelemetrySendTo(process.env.MCP_APP_TELEMETRY_ENV);
  const baseUrl = baseUrlFor(sendTo);
  const logger = adaptLogger(opts.logger ?? defaultLoggerBase);
  let optedIn = false;

  // `.mcpb` installs launch the MCP child without setting `NODE_ENV`, so
  // we opt **into** dev mode only when it's set explicitly to
  // `development`. The previous `!== "production"` check made dev the
  // default for every end-user install, which produced noisy shipper
  // logs in the host's stderr pane.
  const ebt = createAnalytics({
    isDev: process.env.NODE_ENV === "development",
    logger,
  });

  ebt.registerShipper(ElasticV3ServerShipper, {
    channelName: CHANNEL_NAME,
    version: opts.mcpAppVersion,
    buildShipperHeaders: (clusterUuid, version, licenseId) => ({
      "content-type": "application/x-ndjson",
      "x-elastic-cluster-id": clusterUuid,
      "x-elastic-stack-version": version,
      ...(licenseId ? { "x-elastic-license-id": licenseId } : {}),
    }),
    buildShipperUrl: ({ channelName }) => `${baseUrl}/v3/send/${channelName}`,
  });

  // Fail-closed at construction. The TelemetryService will flip this on
  // once it has confirmed the user's Kibana opt-in is `true`.
  ebt.optIn({ global: { enabled: false } });

  ebt.registerEventType(mcpToolCalledEventDef);
  ebt.registerEventType(viewRenderedEventDef);

  const cluster$ = new BehaviorSubject<ClusterContext | undefined>(undefined);
  const license$ = new BehaviorSubject<LicenseContext | undefined>(undefined);

  ebt.registerContextProvider({
    name: "elasticsearch info",
    // The shipper tolerates `undefined` until the first real value lands —
    // it just won't ship until `cluster_uuid` is present, which is exactly
    // the fail-closed behaviour we want.
    context$: cluster$,
    schema: {
      cluster_uuid: {
        type: "keyword",
        _meta: { description: "Elasticsearch cluster UUID" },
      },
      cluster_version: {
        type: "keyword",
        _meta: { description: "Elasticsearch / stack version" },
      },
    },
  });

  ebt.registerContextProvider({
    name: "license info",
    context$: license$,
    schema: {
      license_id: {
        type: "keyword",
        _meta: { description: "License id", optional: true },
      },
      license_status: {
        type: "keyword",
        _meta: { description: "License status", optional: true },
      },
      license_type: {
        type: "keyword",
        _meta: { description: "License type", optional: true },
      },
    },
  });

  const mcpApp$ = new BehaviorSubject<{ mcp_app_version: string }>({
    mcp_app_version: opts.mcpAppVersion,
  });
  ebt.registerContextProvider({
    name: "mcp app info",
    context$: mcpApp$,
    schema: {
      mcp_app_version: {
        type: "keyword",
        _meta: { description: "Version of the Elastic Security MCP App" },
      },
    },
  });

  return {
    trackToolCalled(event: McpToolCalledEbtPayload): void {
      ebt.reportEvent(EVENT_TYPES.mcpToolCalled, event);
      if (optedIn) {
        logReportedEvent(logger, sendTo, EVENT_TYPES.mcpToolCalled, event);
      }
    },
    trackViewRendered(event: ViewRenderedEbtPayload): void {
      ebt.reportEvent(EVENT_TYPES.viewRendered, event);
      if (optedIn) {
        logReportedEvent(logger, sendTo, EVENT_TYPES.viewRendered, event);
      }
    },
    setOptIn(enabled: boolean): void {
      optedIn = enabled;
      ebt.optIn({ global: { enabled } });
    },
    setClusterContext(ctx: ClusterContext): void {
      cluster$.next(ctx);
    },
    setLicenseContext(ctx: LicenseContext): void {
      license$.next(ctx);
    },
    async shutdown(): Promise<void> {
      await ebt.shutdown();
    },
  };
}

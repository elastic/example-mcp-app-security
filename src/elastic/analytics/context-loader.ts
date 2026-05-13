/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsClient } from "../es-client/index.js";
import type { AnalyticsClient } from "./analytics-client.js";

/**
 * Minimal shape of `GET /` on Elasticsearch — we only consume the two
 * fields the analytics context needs, so the type is intentionally
 * narrow. `cluster_name` is deliberately not read: it's user-controlled
 * and would compromise the anonymised framing of the telemetry feed.
 */
interface EsRootResponse {
  readonly cluster_uuid?: string;
  readonly version?: { readonly number?: string };
}

/**
 * Minimal shape of `GET /_license` on Elasticsearch — only what the
 * analytics context schema needs.
 */
interface EsLicenseResponse {
  readonly license?: {
    readonly uid?: string;
    readonly status?: string;
    readonly type?: string;
  };
}

export interface ContextLoader {
  /**
   * One-shot fetch of cluster + license information, applied to the
   * analytics client via `setClusterContext` / `setLicenseContext`.
   *
   * Failures are logged and swallowed: a missing context just means
   * the EBT shipper won't ship until something fills it in (fail-closed).
   */
  loadAndApply(): Promise<void>;
}

export interface CreateContextLoaderDeps {
  readonly esClient: EsClient;
  readonly analytics: Pick<
    AnalyticsClient,
    "setClusterContext" | "setLicenseContext"
  >;
  readonly logger?: Pick<Console, "warn">;
}

/**
 * Build a {@link ContextLoader} that publishes default-cluster
 * Elasticsearch identity into the analytics context on startup.
 *
 * Each half (cluster info, license info) is fetched independently —
 * a missing license still allows cluster context to be applied.
 */
export function createContextLoader(
  deps: CreateContextLoaderDeps,
): ContextLoader {
  const { esClient, analytics, logger = console } = deps;

  return {
    async loadAndApply(): Promise<void> {
      await Promise.all([loadCluster(), loadLicense()]);

      async function loadCluster(): Promise<void> {
        try {
          const { data } = await esClient.get<EsRootResponse>("/");
          if (!data.cluster_uuid || !data.version?.number) {
            logger.warn(
              "[telemetry] elasticsearch root response missing required cluster fields; skipping cluster context",
            );
            return;
          }
          analytics.setClusterContext({
            cluster_uuid: data.cluster_uuid,
            cluster_version: data.version.number,
          });
        } catch (err) {
          logger.warn(
            `[telemetry] failed to load cluster context: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      }

      async function loadLicense(): Promise<void> {
        try {
          const { data } = await esClient.get<EsLicenseResponse>("/_license");
          if (!data.license) return;
          analytics.setLicenseContext({
            license_id: data.license.uid,
            license_status: data.license.status,
            license_type: data.license.type,
          });
        } catch (err) {
          logger.warn(
            `[telemetry] failed to load license context: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
      }
    },
  };
}

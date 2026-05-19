/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  AlertContext,
  AlertSummary,
  NetworkEvent,
  ProcessEvent,
  SecurityAlert,
} from "../../shared/types.js";
import type { AlertsClient } from "../client/alertsClient.js";

/** Time window (ms) on either side of an alert used to gather host context. */
const CONTEXT_WINDOW_MS = 5 * 60 * 1000;

/**
 * Fields searched (wildcard, case-insensitive) when callers pass a free-text
 * `query`. Every term must match at least one of these fields.
 */
const ALERT_QUERY_FIELDS: readonly string[] = [
  "kibana.alert.rule.name",
  "kibana.alert.reason",
  "kibana.alert.rule.description",
  "host.name",
  "user.name",
  "process.name",
  "process.executable",
  "file.name",
  "file.path",
];

interface GetAlertsOptions {
  readonly days?: number;
  readonly severity?: string;
  readonly limit?: number;
  readonly status?: string;
  readonly query?: string;
  /**
   * Kibana space ID whose alerts index to query. Defaults to `default` so
   * the tool matches what the Kibana UI shows when not explicitly scoped.
   * For a deployment-wide view, callers enumerate spaces via
   * `list-namespaces` and pass each id explicitly.
   */
  readonly namespace?: string;
}

interface TimeRange {
  readonly gte: string;
  readonly lte: string;
}

interface AlertsServiceOptions {
  readonly alertsClient: AlertsClient;
}

/**
 * Elasticsearch query clause shape (e.g. `{ range: ... }`, `{ term: ... }`,
 * `{ bool: ... }`). Each property's value is opaque so the type stays
 * permissive across the various clause shapes ES accepts.
 */
type QueryClause = Record<string, unknown>;

/**
 * Business logic for the alert-triage feature.
 *
 * Builds Elasticsearch queries, fans out parallel context lookups, and
 * shapes raw ES responses into the {@link AlertSummary} / {@link AlertContext}
 * domain types consumed by tools and views. Stateless — safe to construct
 * per request.
 */
export class AlertsService {
  constructor(private readonly options: AlertsServiceOptions) {}

  /**
   * Search alerts and return a summary with severity / rule / host
   * aggregations alongside the raw hits.
   *
   * Defaults: last 7 days, `open` workflow status, 50 hits, all severities.
   */
  async getAlerts(options: GetAlertsOptions = {}): Promise<AlertSummary> {
    const {
      days = 7,
      severity,
      limit = 50,
      status = "open",
      query,
      namespace,
    } = options;

    const must: QueryClause[] = [
      { range: { "@timestamp": { gte: `now-${days}d`, lte: "now" } } },
    ];
    if (status) {
      must.push({ term: { "kibana.alert.workflow_status": status } });
    }
    if (severity) {
      must.push({ term: { "kibana.alert.severity": severity } });
    }
    const queryClause = buildQueryClause(query);
    if (queryClause) {
      must.push(queryClause);
    }

    const response = await this.options.alertsClient.searchAlerts(
      {
        size: limit,
        sort: [{ "@timestamp": "asc" }],
        query: { bool: { must } },
        aggs: {
          by_severity: { terms: { field: "kibana.alert.severity", size: 10 } },
          by_rule: { terms: { field: "kibana.alert.rule.name", size: 20 } },
          by_host: { terms: { field: "host.name", size: 20 } },
        },
      },
      namespace
    );

    const aggs = response.aggregations;
    return {
      total: response.hits.total.value,
      bySeverity: Object.fromEntries(
        (aggs?.by_severity.buckets ?? []).map((b) => [b.key, b.doc_count])
      ),
      byRule: (aggs?.by_rule.buckets ?? []).map((b) => ({
        name: b.key,
        count: b.doc_count,
      })),
      byHost: (aggs?.by_host.buckets ?? []).map((b) => ({
        name: b.key,
        count: b.doc_count,
      })),
      alerts: response.hits.hits,
    };
  }

  /**
   * Build investigation context for a single alert by fetching, in parallel:
   *   - endpoint process events on the same host within ±5 minutes
   *   - endpoint network events on the same host within ±5 minutes
   *   - other alerts in the same window correlated by `host.name` or `agent.id`
   *
   * `alert` is required (not re-fetched) because callers typically already
   * have the source document from a prior `getAlerts` call.
   */
  async getAlertContext(
    alertId: string,
    alert: SecurityAlert,
    namespace?: string
  ): Promise<AlertContext> {
    const src = alert._source;
    const center = new Date(src["@timestamp"]).getTime();
    const timeRange: TimeRange = {
      gte: new Date(center - CONTEXT_WINDOW_MS).toISOString(),
      lte: new Date(center + CONTEXT_WINDOW_MS).toISOString(),
    };
    const hostName = src.host?.name;
    const agentId = src.agent?.id;

    const [processEvents, networkEvents, relatedAlerts] = await Promise.all([
      this.getProcessEvents(hostName, timeRange),
      this.getNetworkEvents(hostName, timeRange),
      this.getRelatedAlerts(alertId, hostName, agentId, timeRange, namespace),
    ]);

    return { processEvents, networkEvents, relatedAlerts };
  }

  /**
   * Mark a single alert as `acknowledged`. Delegates to the bulk path because
   * `_update_by_query` is what we use to scope the write to a single
   * namespace's alerts index.
   */
  async acknowledgeAlert(alertId: string, namespace?: string): Promise<void> {
    await this.acknowledgeAlerts([alertId], namespace);
  }

  /**
   * Mark many alerts as `acknowledged` via `_update_by_query`.
   *
   * @returns number of documents actually updated, as reported by Elasticsearch
   */
  async acknowledgeAlerts(
    alertIds: readonly string[],
    namespace?: string
  ): Promise<{ updated: number }> {
    return this.setAlertWorkflowStatus(alertIds, "acknowledged", namespace);
  }

  /**
   * Set the workflow status (`open` | `acknowledged` | `closed`) on a set of
   * security alerts in bulk. Used by the acknowledge / unacknowledge tools so
   * the Alert Triage UI can offer an Undo affordance after acknowledging.
   */
  async setAlertWorkflowStatus(
    alertIds: readonly string[],
    status: "open" | "acknowledged" | "closed",
    namespace?: string
  ): Promise<{ updated: number }> {
    if (alertIds.length === 0) return { updated: 0 };
    const result = await this.options.alertsClient.updateAlertsByQuery(
      {
        query: { ids: { values: alertIds } },
        script: {
          source: 'ctx._source["kibana.alert.workflow_status"] = params.status',
          lang: "painless",
          params: { status },
        },
      },
      namespace
    );
    return { updated: result.updated };
  }

  private async getProcessEvents(
    hostName: string | undefined,
    timeRange: TimeRange
  ): Promise<ProcessEvent[]> {
    if (!hostName) return [];
    const response = await this.options.alertsClient.searchProcessEvents(
      buildHostEventQuery(hostName, timeRange)
    );
    return response.hits.hits.map((h) => h._source);
  }

  private async getNetworkEvents(
    hostName: string | undefined,
    timeRange: TimeRange
  ): Promise<NetworkEvent[]> {
    if (!hostName) return [];
    const response = await this.options.alertsClient.searchNetworkEvents(
      buildHostEventQuery(hostName, timeRange)
    );
    return response.hits.hits.map((h) => h._source);
  }

  private async getRelatedAlerts(
    alertId: string,
    hostName: string | undefined,
    agentId: string | undefined,
    timeRange: TimeRange,
    namespace?: string
  ): Promise<SecurityAlert[]> {
    const should: QueryClause[] = [
      ...(hostName ? [{ term: { "host.name": hostName } }] : []),
      ...(agentId ? [{ term: { "agent.id": agentId } }] : []),
    ];
    if (should.length === 0) return [];

    const response = await this.options.alertsClient.searchAlerts(
      {
        size: 20,
        sort: [{ "@timestamp": "asc" }],
        query: {
          bool: {
            must: [{ range: { "@timestamp": timeRange } }],
            should,
            minimum_should_match: 1,
            must_not: [{ term: { _id: alertId } }],
          },
        },
      },
      namespace
    );
    return [...response.hits.hits];
  }
}

function buildHostEventQuery(
  hostName: string,
  timeRange: TimeRange
): QueryClause {
  return {
    size: 100,
    sort: [{ "@timestamp": "asc" }],
    query: {
      bool: {
        must: [
          { range: { "@timestamp": timeRange } },
          { term: { "host.name": hostName } },
        ],
      },
    },
  };
}

/**
 * Translate a free-text query into a `bool` clause that ANDs each whitespace-
 * separated term, where each term must wildcard-match at least one of
 * {@link ALERT_QUERY_FIELDS}. Returns `null` for an empty / whitespace-only
 * query so callers can skip pushing anything onto the parent `must` list.
 */
function buildQueryClause(query: string | undefined): QueryClause | null {
  if (!query) return null;
  const terms = query.trim().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return null;

  const termClauses = terms.map((term) => ({
    bool: {
      should: ALERT_QUERY_FIELDS.map((field) => ({
        wildcard: {
          [field]: {
            value: `*${term.toLowerCase()}*`,
            case_insensitive: true,
          },
        },
      })),
      minimum_should_match: 1,
    },
  }));

  if (termClauses.length === 1) return termClauses[0];
  return { bool: { should: termClauses, minimum_should_match: 1 } };
}

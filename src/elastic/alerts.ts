import { esRequest, kibanaRequest } from "./client.js";
import type { SecurityAlert, AlertSummary, AlertContext, ProcessEvent, NetworkEvent } from "../shared/types.js";

const ALERTS_INDEX = ".alerts-security.alerts-*";

export async function fetchAlerts(options: {
  days?: number;
  severity?: string;
  limit?: number;
  status?: string;
  query?: string;
}): Promise<AlertSummary> {
  const { days = 7, severity, limit = 50, status = "open", query } = options;
  const must: unknown[] = [
    { range: { "@timestamp": { gte: `now-${days}d`, lte: "now" } } },
  ];

  if (status) {
    must.push({ term: { "kibana.alert.workflow_status": status } });
  }
  if (severity) {
    must.push({ term: { "kibana.alert.severity": severity } });
  }
  if (query) {
    const wildcardFields = [
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
    const pattern = `*${query.toLowerCase()}*`;
    must.push({
      bool: {
        should: wildcardFields.map((field) => ({
          wildcard: { [field]: { value: pattern, case_insensitive: true } },
        })),
        minimum_should_match: 1,
      },
    });
  }

  const result = await esRequest<{
    hits: { total: { value: number }; hits: SecurityAlert[] };
    aggregations?: {
      by_severity: { buckets: { key: string; doc_count: number }[] };
      by_rule: { buckets: { key: string; doc_count: number }[] };
      by_host: { buckets: { key: string; doc_count: number }[] };
    };
  }>(`/${ALERTS_INDEX}/_search`, {
    body: {
      size: limit,
      sort: [{ "@timestamp": "asc" }],
      query: { bool: { must } },
      aggs: {
        by_severity: { terms: { field: "kibana.alert.severity", size: 10 } },
        by_rule: { terms: { field: "kibana.alert.rule.name", size: 20 } },
        by_host: { terms: { field: "host.name", size: 20 } },
      },
    },
  });

  const aggs = result.aggregations;
  return {
    total: result.hits.total.value,
    bySeverity: Object.fromEntries(
      (aggs?.by_severity.buckets || []).map((b) => [b.key, b.doc_count])
    ),
    byRule: (aggs?.by_rule.buckets || []).map((b) => ({
      name: b.key,
      count: b.doc_count,
    })),
    byHost: (aggs?.by_host.buckets || []).map((b) => ({
      name: b.key,
      count: b.doc_count,
    })),
    alerts: result.hits.hits,
  };
}

export async function getAlertContext(
  alertId: string,
  alert: SecurityAlert
): Promise<AlertContext> {
  const src = alert._source;
  const timestamp = src["@timestamp"];
  const hostName = src.host?.name;
  const agentId = src.agent?.id;
  const timeRange = {
    gte: new Date(new Date(timestamp).getTime() - 5 * 60 * 1000).toISOString(),
    lte: new Date(new Date(timestamp).getTime() + 5 * 60 * 1000).toISOString(),
  };

  const processQuery = hostName
    ? esRequest<{ hits: { hits: { _source: ProcessEvent }[] } }>(
        "/logs-endpoint.events.process-*/_search",
        {
          body: {
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
          },
        }
      )
    : Promise.resolve({ hits: { hits: [] } });

  const networkQuery = hostName
    ? esRequest<{ hits: { hits: { _source: NetworkEvent }[] } }>(
        "/logs-endpoint.events.network-*/_search",
        {
          body: {
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
          },
        }
      )
    : Promise.resolve({ hits: { hits: [] } });

  const relatedQuery = esRequest<{ hits: { hits: SecurityAlert[] } }>(
    `/${ALERTS_INDEX}/_search`,
    {
      body: {
        size: 20,
        sort: [{ "@timestamp": "asc" }],
        query: {
          bool: {
            must: [{ range: { "@timestamp": timeRange } }],
            should: [
              ...(hostName ? [{ term: { "host.name": hostName } }] : []),
              ...(agentId ? [{ term: { "agent.id": agentId } }] : []),
            ],
            minimum_should_match: 1,
            must_not: [{ term: { _id: alertId } }],
          },
        },
      },
    }
  );

  const [processResult, networkResult, relatedResult] = await Promise.all([
    processQuery,
    networkQuery,
    relatedQuery,
  ]);

  return {
    processEvents: processResult.hits.hits.map((h) => h._source),
    networkEvents: networkResult.hits.hits.map((h) => h._source),
    relatedAlerts: relatedResult.hits.hits,
  };
}

export async function acknowledgeAlert(alertId: string): Promise<void> {
  await esRequest(`/${ALERTS_INDEX}/_update/${alertId}`, {
    body: {
      doc: { "kibana.alert.workflow_status": "acknowledged" },
    },
  });
}

export async function acknowledgeAlerts(alertIds: string[]): Promise<{ updated: number }> {
  const result = await esRequest<{ updated: number }>(
    `/${ALERTS_INDEX}/_update_by_query`,
    {
      body: {
        query: { ids: { values: alertIds } },
        script: {
          source: 'ctx._source["kibana.alert.workflow_status"] = "acknowledged"',
          lang: "painless",
        },
      },
    }
  );
  return { updated: result.updated };
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsqlResult } from "../../shared/types.js";
import type {
  AnonymizationField,
  AttackDiscovery,
  AttackDiscoveryClient,
  ConfidenceLevel,
  ConfidenceSignals,
  DiscoverySummary,
  GenerationResult,
  TriagedDiscovery,
} from "../client/attackDiscoveryClient.js";

const DEFAULT_NAMESPACE = "default";
const RISK_INDEX = "risk-score.risk-score-latest-*";

/**
 * Helpers that compute the three space-scoped indices the attack-discovery
 * feature reads from. Defaulting `namespace` to `"default"` keeps existing
 * single-space deployments behaving the same; pass an explicit namespace
 * for multi-space queries.
 */
function scheduledIndex(namespace?: string): string {
  return `.alerts-security.attack.discovery.alerts-${namespace || DEFAULT_NAMESPACE}`;
}
function adhocIndex(namespace?: string): string {
  return `.adhoc.alerts-security.attack.discovery.alerts-${namespace || DEFAULT_NAMESPACE}`;
}
function alertsIndex(namespace?: string): string {
  return `.alerts-security.alerts-${namespace || DEFAULT_NAMESPACE}`;
}

interface AttackDiscoveryServiceOptions {
  readonly attackDiscoveryClient: AttackDiscoveryClient;
}

interface DiscoveryDetail {
  titleWithReplacements: string;
  summaryWithReplacements: string;
  detailsWithReplacements: string;
  alerts: {
    id: string;
    ruleName: string;
    severity: string;
    host: string;
    user: string;
    timestamp: string;
    details: Record<string, string>;
  }[];
  entityRisk: { name: string; type: string; level: string; score: number }[];
}

interface GenerateAttackDiscoveryInput {
  connectorId: string;
  actionTypeId: string;
  connectorName?: string;
  size?: number;
  start?: string;
  end?: string;
  filter?: Record<string, unknown>;
  /**
   * Kibana space ID to scope the generation request to. Also determines
   * which alerts index the LLM analyzes (`.alerts-security.alerts-<ns>`).
   */
  namespace?: string;
}

/**
 * Business logic for attack discoveries: ES|QL fetch with index-fallback,
 * confidence-signal synthesis, ack across both scheduled + adhoc indices,
 * detail-view assembly with replacement-marker injection, on-demand
 * generation with always-allowed `_id`, and AI connector listing filtered
 * to the supported action types.
 */
export class AttackDiscoveryService {
  constructor(private readonly options: AttackDiscoveryServiceOptions) {}

  /**
   * Fetch open attack discoveries.
   *
   * Tries the multi-index ES|QL query first; if that fails (typically
   * because one of the two indices does not yet exist on this cluster),
   * falls back to issuing the same query against each index individually
   * and merging the rows.
   */
  async getDiscoveries(options: {
    days?: number;
    limit?: number;
    namespace?: string;
  }): Promise<DiscoverySummary> {
    const { days = 1, limit = 50, namespace } = options;
    const scheduled_index = scheduledIndex(namespace);
    const adhoc_index = adhocIndex(namespace);

    const query = `FROM ${scheduled_index}, ${adhoc_index} METADATA _id
| WHERE kibana.alert.workflow_status == "open"
  AND @timestamp >= NOW() - ${days} day
| KEEP @timestamp, _id,
       kibana.alert.rule.execution.uuid,
       kibana.alert.attack_discovery.title,
       kibana.alert.attack_discovery.summary_markdown,
       kibana.alert.attack_discovery.details_markdown,
       kibana.alert.attack_discovery.mitre_attack_tactics,
       kibana.alert.attack_discovery.alert_ids,
       kibana.alert.attack_discovery.alerts_context_count,
       kibana.alert.risk_score
| SORT kibana.alert.risk_score DESC, @timestamp DESC
| LIMIT ${limit}`;

    let result = await this.safeEsql(query);

    if (!result) {
      const scheduled = await this.safeEsql(
        query.replace(
          `${scheduled_index}, ${adhoc_index} METADATA _id`,
          `${scheduled_index} METADATA _id`
        )
      );
      const adhoc = await this.safeEsql(
        query.replace(
          `${scheduled_index}, ${adhoc_index} METADATA _id`,
          `${adhoc_index} METADATA _id`
        )
      );
      if (scheduled && adhoc) {
        result = {
          columns: scheduled.columns,
          values: [...scheduled.values, ...adhoc.values],
        };
      } else {
        result = scheduled || adhoc;
      }
    }

    if (!result || result.values.length === 0) {
      return { total: 0, discoveries: [] };
    }

    const finalResult = result;
    const col = (name: string) =>
      finalResult.columns.findIndex((c) => c.name === name);

    const discoveries: AttackDiscovery[] = finalResult.values.map((row) => {
      const alertIds = row[col("kibana.alert.attack_discovery.alert_ids")];
      const tactics =
        row[col("kibana.alert.attack_discovery.mitre_attack_tactics")];

      return {
        id: String(row[col("_id")] || ""),
        timestamp: String(row[col("@timestamp")] || ""),
        executionUuid: String(
          row[col("kibana.alert.rule.execution.uuid")] || ""
        ),
        title: String(row[col("kibana.alert.attack_discovery.title")] || ""),
        summaryMarkdown: String(
          row[col("kibana.alert.attack_discovery.summary_markdown")] || ""
        ),
        detailsMarkdown: String(
          row[col("kibana.alert.attack_discovery.details_markdown")] || ""
        ),
        mitreTactics: Array.isArray(tactics)
          ? tactics.map(String)
          : typeof tactics === "string"
            ? [tactics]
            : [],
        alertIds: Array.isArray(alertIds) ? alertIds.map(String) : [],
        alertsContextCount: Number(
          row[col("kibana.alert.attack_discovery.alerts_context_count")] || 0
        ),
        riskScore: Number(row[col("kibana.alert.risk_score")] || 0),
      };
    });

    return { total: discoveries.length, discoveries };
  }

  async assessConfidence(
    discoveries: AttackDiscovery[],
    namespace?: string
  ): Promise<TriagedDiscovery[]> {
    const alerts_index = alertsIndex(namespace);
    const allAlertIds = [...new Set(discoveries.flatMap((d) => d.alertIds))];

    if (allAlertIds.length === 0) {
      return discoveries.map((d) => ({
        ...d,
        confidence: "low" as ConfidenceLevel,
        signals: {
          alertDiversity: { alertCount: 0, ruleCount: 0, severities: [] },
          ruleFrequency: [],
          entityRisk: [],
        },
        hosts: [],
        users: [],
        ruleNames: [],
      }));
    }

    const idsClause = allAlertIds.map((id) => `"${escapeEsql(id)}"`).join(", ");
    const diversityResult = await this.safeEsql(`FROM ${alerts_index} METADATA _id
| WHERE _id IN (${idsClause})
  AND kibana.alert.workflow_status == "open"
| KEEP _id, kibana.alert.rule.name, kibana.alert.rule.uuid, kibana.alert.severity, host.name, user.name, agent.id`);

    interface AlertRow {
      id: string;
      ruleName: string;
      ruleUuid: string;
      severity: string;
      hostName: string;
      userName: string;
      agentId: string;
    }

    const alertRows: AlertRow[] = [];
    if (diversityResult) {
      const dc = (name: string) =>
        diversityResult.columns.findIndex((c) => c.name === name);
      for (const row of diversityResult.values) {
        alertRows.push({
          id: String(row[dc("_id")] || ""),
          ruleName: String(row[dc("kibana.alert.rule.name")] || ""),
          ruleUuid: String(row[dc("kibana.alert.rule.uuid")] || ""),
          severity: String(row[dc("kibana.alert.severity")] || ""),
          hostName: String(row[dc("host.name")] || ""),
          userName: String(row[dc("user.name")] || ""),
          agentId: String(row[dc("agent.id")] || ""),
        });
      }
    }

    const allRuleNames = [
      ...new Set(alertRows.map((r) => r.ruleName).filter(Boolean)),
    ];
    const allHosts = [
      ...new Set(
        alertRows.map((r) => r.hostName).filter((v) => v && v !== "null")
      ),
    ];
    const allUsers = [
      ...new Set(
        alertRows.map((r) => r.userName).filter((v) => v && v !== "null")
      ),
    ];

    const ruleFreqMap = new Map<string, { total: number; hosts: number }>();
    if (allRuleNames.length > 0) {
      const ruleClause = allRuleNames
        .map((r) => `"${escapeEsql(r)}"`)
        .join(", ");
      const ruleResult = await this.safeEsql(`FROM ${alerts_index}
| WHERE kibana.alert.rule.name IN (${ruleClause})
  AND @timestamp >= NOW() - 7 day
| STATS total = COUNT(*), hosts = COUNT_DISTINCT(host.name)
  BY kibana.alert.rule.name`);
      if (ruleResult) {
        const rc = (name: string) =>
          ruleResult.columns.findIndex((c) => c.name === name);
        for (const row of ruleResult.values) {
          const name = String(row[rc("kibana.alert.rule.name")] || "");
          ruleFreqMap.set(name, {
            total: Number(row[rc("total")] || 0),
            hosts: Number(row[rc("hosts")] || 0),
          });
        }
      }
    }

    const entityRiskMap = new Map<
      string,
      { type: "host" | "user"; level: string; score: number }
    >();
    if (allHosts.length > 0 || allUsers.length > 0) {
      const clauses: string[] = [];
      if (allHosts.length > 0) {
        clauses.push(
          `host.name IN (${allHosts.map((h) => `"${escapeEsql(h)}"`).join(", ")})`
        );
      }
      if (allUsers.length > 0) {
        clauses.push(
          `user.name IN (${allUsers.map((u) => `"${escapeEsql(u)}"`).join(", ")})`
        );
      }
      const riskResult = await this.safeEsql(`FROM ${RISK_INDEX}
| WHERE ${clauses.join(" OR ")}
| KEEP host.name, user.name,
       host.risk.calculated_level, host.risk.calculated_score_norm,
       user.risk.calculated_level, user.risk.calculated_score_norm`);
      if (riskResult) {
        const ec = (name: string) =>
          riskResult.columns.findIndex((c) => c.name === name);
        for (const row of riskResult.values) {
          const hostName = String(row[ec("host.name")] || "");
          const userName = String(row[ec("user.name")] || "");
          if (hostName && hostName !== "null") {
            entityRiskMap.set(`host:${hostName}`, {
              type: "host",
              level: String(row[ec("host.risk.calculated_level")] || "Unknown"),
              score: Number(row[ec("host.risk.calculated_score_norm")] || 0),
            });
          }
          if (userName && userName !== "null") {
            entityRiskMap.set(`user:${userName}`, {
              type: "user",
              level: String(row[ec("user.risk.calculated_level")] || "Unknown"),
              score: Number(row[ec("user.risk.calculated_score_norm")] || 0),
            });
          }
        }
      }
    }

    return discoveries.map((d) => {
      const findingAlerts = alertRows.filter((r) => d.alertIds.includes(r.id));
      const findingRules = [
        ...new Set(findingAlerts.map((a) => a.ruleName).filter(Boolean)),
      ];
      const findingHosts = [
        ...new Set(
          findingAlerts.map((a) => a.hostName).filter((v) => v && v !== "null")
        ),
      ];
      const findingUsers = [
        ...new Set(
          findingAlerts.map((a) => a.userName).filter((v) => v && v !== "null")
        ),
      ];
      const findingSeverities = [
        ...new Set(findingAlerts.map((a) => a.severity).filter(Boolean)),
      ];

      const ruleFrequency = findingRules.map((name) => {
        const freq = ruleFreqMap.get(name) || { total: 0, hosts: 0 };
        return {
          ruleName: name,
          totalAlerts7d: freq.total,
          hostCount: freq.hosts,
        };
      });

      const entityRisk = [
        ...findingHosts.map((h) => {
          const risk = entityRiskMap.get(`host:${h}`);
          return {
            name: h,
            type: "host" as const,
            riskLevel: risk?.level || "Unknown",
            riskScore: risk?.score || 0,
          };
        }),
        ...findingUsers.map((u) => {
          const risk = entityRiskMap.get(`user:${u}`);
          return {
            name: u,
            type: "user" as const,
            riskLevel: risk?.level || "Unknown",
            riskScore: risk?.score || 0,
          };
        }),
      ];

      const signals: ConfidenceSignals = {
        alertDiversity: {
          alertCount: findingAlerts.length,
          ruleCount: findingRules.length,
          severities: findingSeverities,
        },
        ruleFrequency,
        entityRisk,
      };

      const confidence = synthesizeConfidence(signals);

      return {
        ...d,
        confidence,
        signals,
        hosts: findingHosts,
        users: findingUsers,
        ruleNames: findingRules,
      };
    });
  }

  /**
   * Mark `discoveryIds` as `acknowledged` across both the scheduled and the
   * adhoc indices. Per-index failures are swallowed so a missing index does
   * not abort the operation; the returned `updated` count is the sum across
   * indices that did respond.
   */
  async acknowledgeDiscoveries(
    discoveryIds: string[],
    namespace?: string
  ): Promise<{ updated: number }> {
    let totalUpdated = 0;

    for (const index of [scheduledIndex(namespace), adhocIndex(namespace)]) {
      try {
        const result =
          await this.options.attackDiscoveryClient.acknowledgeOnIndex(index, {
            query: { ids: { values: discoveryIds } },
            script: {
              source:
                'ctx._source["kibana.alert.workflow_status"] = "acknowledged"',
              lang: "painless",
            },
          });
        totalUpdated += result.updated || 0;
      } catch {
        // index may not exist
      }
    }

    return { updated: totalUpdated };
  }

  async getDiscoveryDetail(
    discovery: AttackDiscovery,
    namespace?: string
  ): Promise<DiscoveryDetail> {
    const alerts_index = alertsIndex(namespace);
    const scheduled_index = scheduledIndex(namespace);
    const adhoc_index = adhocIndex(namespace);
    const alertIds = discovery.alertIds || [];
    let alerts: DiscoveryDetail["alerts"] = [];

    if (alertIds.length > 0) {
      const idsClause = alertIds.map((id) => `"${escapeEsql(id)}"`).join(", ");
      const result = await this.safeEsql(`FROM ${alerts_index} METADATA _id
| WHERE _id IN (${idsClause})
| KEEP _id, kibana.alert.rule.name, kibana.alert.severity, kibana.alert.rule.description,
       kibana.alert.risk_score, kibana.alert.reason,
       host.name, user.name, process.name, process.executable,
       file.name, file.path, source.ip, destination.ip, @timestamp
| SORT @timestamp DESC`);
      if (result) {
        const c = (name: string) =>
          result.columns.findIndex((col) => col.name === name);
        const str = (row: unknown[], col: string) => {
          const idx = c(col);
          const v = idx >= 0 ? row[idx] : null;
          return v != null && String(v) !== "null" ? String(v) : "";
        };
        alerts = result.values.map((row) => {
          const details: Record<string, string> = {};
          const fields: [string, string][] = [
            ["host.name", "host.name"],
            ["user.name", "user.name"],
            ["process.name", "process.name"],
            ["process.executable", "process.executable"],
            ["file.name", "file.name"],
            ["file.path", "file.path"],
            ["source.ip", "source.ip"],
            ["destination.ip", "destination.ip"],
            ["kibana.alert.rule.description", "rule.description"],
            ["kibana.alert.risk_score", "risk_score"],
            ["kibana.alert.reason", "reason"],
          ];
          for (const [esField, label] of fields) {
            const v = str(row, esField);
            if (v) details[label] = v;
          }
          return {
            id: str(row, "_id"),
            ruleName: str(row, "kibana.alert.rule.name"),
            severity: str(row, "kibana.alert.severity"),
            host: str(row, "host.name"),
            user: str(row, "user.name"),
            timestamp: str(row, "@timestamp"),
            details,
          };
        });
      }
    }

    const hosts = [
      ...new Set(alerts.map((a) => a.host).filter((v) => v && v !== "null")),
    ];
    const users = [
      ...new Set(alerts.map((a) => a.user).filter((v) => v && v !== "null")),
    ];

    const riskMap = new Map<string, { level: string; score: number }>();
    if (hosts.length > 0 || users.length > 0) {
      const clauses: string[] = [];
      if (hosts.length > 0) {
        clauses.push(
          `host.name IN (${hosts.map((h) => `"${escapeEsql(h)}"`).join(", ")})`
        );
      }
      if (users.length > 0) {
        clauses.push(
          `user.name IN (${users.map((u) => `"${escapeEsql(u)}"`).join(", ")})`
        );
      }
      const riskResult = await this.safeEsql(`FROM ${RISK_INDEX}
| WHERE ${clauses.join(" OR ")}
| KEEP host.name, user.name,
       host.risk.calculated_level, host.risk.calculated_score_norm,
       user.risk.calculated_level, user.risk.calculated_score_norm`);
      if (riskResult) {
        const ec = (name: string) =>
          riskResult.columns.findIndex((col) => col.name === name);
        for (const row of riskResult.values) {
          const hostName = String(row[ec("host.name")] || "");
          const userName = String(row[ec("user.name")] || "");
          if (hostName && hostName !== "null") {
            riskMap.set(`host:${hostName}`, {
              level: String(row[ec("host.risk.calculated_level")] || "Unknown"),
              score: Number(row[ec("host.risk.calculated_score_norm")] || 0),
            });
          }
          if (userName && userName !== "null") {
            riskMap.set(`user:${userName}`, {
              level: String(row[ec("user.risk.calculated_level")] || "Unknown"),
              score: Number(row[ec("user.risk.calculated_score_norm")] || 0),
            });
          }
        }
      }
    }

    const entityRisk: DiscoveryDetail["entityRisk"] = [
      ...hosts.map((h) => {
        const risk = riskMap.get(`host:${h}`);
        return {
          name: h,
          type: "host",
          level: risk?.level || "Unknown",
          score: risk?.score || 0,
        };
      }),
      ...users.map((u) => {
        const risk = riskMap.get(`user:${u}`);
        return {
          name: u,
          type: "user",
          level: risk?.level || "Unknown",
          score: risk?.score || 0,
        };
      }),
    ];

    const withReplacementsResult =
      await this.safeEsql(`FROM ${scheduled_index}, ${adhoc_index} METADATA _id
| WHERE _id == "${escapeEsql(discovery.id)}"
| KEEP kibana.alert.attack_discovery.title_with_replacements,
       kibana.alert.attack_discovery.summary_markdown_with_replacements,
       kibana.alert.attack_discovery.details_markdown_with_replacements`);

    let titleWithReplacements = discovery.title;
    let summaryWithReplacements = discovery.summaryMarkdown;
    let detailsWithReplacements = discovery.detailsMarkdown;

    if (withReplacementsResult && withReplacementsResult.values.length > 0) {
      const wc = (name: string) =>
        withReplacementsResult.columns.findIndex((col) => col.name === name);
      const row = withReplacementsResult.values[0];
      const t =
        row[wc("kibana.alert.attack_discovery.title_with_replacements")];
      const s =
        row[
          wc("kibana.alert.attack_discovery.summary_markdown_with_replacements")
        ];
      const d =
        row[
          wc("kibana.alert.attack_discovery.details_markdown_with_replacements")
        ];
      if (t) titleWithReplacements = String(t);
      if (s) summaryWithReplacements = String(s);
      if (d) detailsWithReplacements = String(d);
    }

    const hasMarkers =
      /\{\{/.test(titleWithReplacements) ||
      /\{\{/.test(summaryWithReplacements) ||
      /\{\{/.test(detailsWithReplacements);
    if (!hasMarkers) {
      const inject = (text: string): string => {
        const sorted = [
          ...hosts.map((h) => ({ name: h, field: "host.name" })),
          ...users.map((u) => ({ name: u, field: "user.name" })),
        ].sort((a, b) => b.name.length - a.name.length);
        let injected = text;
        for (const { name, field } of sorted) {
          if (!name) continue;
          const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          injected = injected.replace(
            new RegExp(`(?<!\\{\\{\\s*${field}\\s+)\\b${escaped}\\b`, "g"),
            `{{ ${field} ${name} }}`
          );
        }
        return injected;
      };
      titleWithReplacements = inject(titleWithReplacements);
      summaryWithReplacements = inject(summaryWithReplacements);
      detailsWithReplacements = inject(detailsWithReplacements);
    }

    return {
      titleWithReplacements,
      summaryWithReplacements,
      detailsWithReplacements,
      alerts,
      entityRisk,
    };
  }

  async generateAttackDiscovery(
    options: GenerateAttackDiscoveryInput
  ): Promise<GenerationResult> {
    const { namespace } = options;
    const anonymizationFields = await this.getAnonymizationFields(namespace);

    return this.options.attackDiscoveryClient.generate(
      {
        alertsIndexPattern: alertsIndex(namespace),
        anonymizationFields,
        apiConfig: {
          connectorId: options.connectorId,
          actionTypeId: options.actionTypeId,
        },
        connectorName: options.connectorName,
        size: options.size || 50,
        subAction: "invokeAI",
        start: options.start || "now-7d",
        end: options.end || "now",
        replacements: {},
        ...(options.filter ? { filter: options.filter } : {}),
      },
      namespace
    );
  }

  /**
   * List recent attack-discovery generations.
   *
   * Returns the raw envelope from Kibana — the UI consumes the shape
   * directly and we deliberately don't narrow it here.
   */
  getGenerations(options: {
    size?: number;
    start?: string;
    end?: string;
    namespace?: string;
  }): Promise<unknown> {
    const params: Record<string, string> = {};
    if (options.size) params.size = String(options.size);
    if (options.start) params.start = options.start;
    if (options.end) params.end = options.end;
    return this.options.attackDiscoveryClient.getGenerations(
      params,
      options.namespace
    );
  }

  async listAIConnectors(
    namespace?: string
  ): Promise<{ id: string; name: string; actionTypeId: string }[]> {
    const all = await this.options.attackDiscoveryClient.listConnectors(
      namespace
    );
    const aiTypes = new Set([".gen-ai", ".bedrock", ".gemini", ".inference"]);
    return all
      .filter((c) =>
        aiTypes.has(c.connector_type_id || c.action_type_id || "")
      )
      .map((c) => ({
        id: c.id,
        name: c.name,
        actionTypeId: c.connector_type_id || c.action_type_id || "",
      }));
  }

  private async getAnonymizationFields(
    namespace?: string
  ): Promise<AnonymizationField[]> {
    const result =
      await this.options.attackDiscoveryClient.findAnonymizationFields(
        namespace
      );
    const fields = result.data || [];

    const hasId = fields.some((f) => f.field === "_id");
    if (!hasId) {
      fields.push({
        field: "_id",
        allowed: true,
        anonymized: false,
        id: "_id_injected",
      });
    } else {
      for (const f of fields) {
        if (f.field === "_id") {
          f.allowed = true;
          f.anonymized = false;
        }
      }
    }

    return fields;
  }

  private async safeEsql(query: string): Promise<EsqlResult | null> {
    try {
      return await this.options.attackDiscoveryClient.runEsql(query);
    } catch {
      return null;
    }
  }
}

function escapeEsql(val: string): string {
  return val.replace(/"/g, '\\"');
}

function synthesizeConfidence(signals: ConfidenceSignals): ConfidenceLevel {
  let score = 0;

  const { alertCount, ruleCount, severities } = signals.alertDiversity;
  if (alertCount >= 5 && ruleCount >= 2) score += 2;
  else if (alertCount >= 3 && ruleCount >= 2) score += 1;

  if (severities.includes("critical")) score += 1;
  if (severities.includes("high")) score += 0.5;

  for (const rf of signals.ruleFrequency) {
    if (rf.totalAlerts7d > 100 && rf.hostCount > 5) score -= 1;
    else if (rf.totalAlerts7d < 10 && rf.hostCount <= 2) score += 1;
  }

  for (const er of signals.entityRisk) {
    if (er.riskLevel === "Critical" || er.riskScore > 90) score += 2;
    else if (er.riskLevel === "High" || er.riskScore > 70) score += 1;
    else if (er.riskLevel === "Low" || er.riskScore < 20) score -= 0.5;
  }

  if (score >= 3) return "high";
  if (score >= 1) return "moderate";
  return "low";
}

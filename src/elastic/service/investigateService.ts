/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  EsqlEnvelope,
  GraphEdge,
  GraphNode,
  InvestigateClient,
  InvestigationResult,
} from "../client/investigateClient.js";

interface InvestigateServiceOptions {
  readonly investigateClient: InvestigateClient;
}

const DEFAULT_NAMESPACE = "default";
function alertsIndex(namespace?: string): string {
  return `.alerts-security.alerts-${namespace || DEFAULT_NAMESPACE}`;
}

/**
 * Business logic for graph-based investigations.
 *
 * Builds ES|QL queries pivoting around an entity (user / host / ip /
 * process), fans them out in parallel, and aggregates the rows into a
 * deduplicated graph of nodes and edges. Failures inside a single sub-query
 * are swallowed (returning `null`) so a single index outage degrades the
 * graph rather than failing the whole investigation.
 */
export class InvestigateService {
  constructor(private readonly options: InvestigateServiceOptions) {}

  async investigateEntity(
    entityType: string,
    entityValue: string,
    timeRange = "now-365d",
    namespace?: string
  ): Promise<InvestigationResult> {
    switch (entityType) {
      case "user":
        return this.investigateUser(entityValue, timeRange, namespace);
      case "host":
        return this.investigateHost(entityValue, timeRange, namespace);
      case "ip":
        return this.investigateIP(entityValue, timeRange);
      case "process":
        return this.investigateProcess(entityValue, timeRange);
      default:
        return { nodes: [], edges: [] };
    }
  }

  private async investigateUser(
    userName: string,
    timeRange: string,
    namespace?: string
  ): Promise<InvestigationResult> {
    const nodes: GraphNode[] = [
      { id: nodeId("user", userName), type: "user", value: userName },
    ];
    const edges: GraphEdge[] = [];
    const seen = new Set<string>([nodes[0].id]);
    const tc = buildTimeClause(timeRange);

    const [processes, hosts, alerts] = await Promise.all([
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE user.name == "${esc(userName)}" ${tc} | STATS count=COUNT(*) BY process.name, host.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE user.name == "${esc(userName)}" ${tc} | STATS count=COUNT(*) BY host.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM ${alertsIndex(namespace)} | WHERE user.name == "${esc(userName)}" ${tc} | STATS count=COUNT(*) BY kibana.alert.rule.name, host.name | SORT count DESC | LIMIT 3`
      ),
    ]);

    addResults(processes, nodes, edges, seen, nodes[0].id, [
      { colName: "process.name", type: "process", edgeLabel: "ran" },
      { colName: "host.name", type: "host", edgeLabel: "on host" },
    ]);

    addResults(hosts, nodes, edges, seen, nodes[0].id, [
      { colName: "host.name", type: "host", edgeLabel: "logged into" },
    ]);

    addResults(alerts, nodes, edges, seen, nodes[0].id, [
      { colName: "kibana.alert.rule.name", type: "alert", edgeLabel: "triggered" },
    ]);

    return { nodes, edges };
  }

  private async investigateHost(
    hostName: string,
    timeRange: string,
    namespace?: string
  ): Promise<InvestigationResult> {
    const nodes: GraphNode[] = [
      { id: nodeId("host", hostName), type: "host", value: hostName },
    ];
    const edges: GraphEdge[] = [];
    const seen = new Set<string>([nodes[0].id]);
    const tc = buildTimeClause(timeRange);

    const [users, processes, network, alerts] = await Promise.all([
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE host.name == "${esc(hostName)}" ${tc} | STATS count=COUNT(*) BY user.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE host.name == "${esc(hostName)}" ${tc} | STATS count=COUNT(*) BY process.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.network-* | WHERE host.name == "${esc(hostName)}" ${tc} | STATS count=COUNT(*) BY destination.ip | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM ${alertsIndex(namespace)} | WHERE host.name == "${esc(hostName)}" ${tc} | STATS count=COUNT(*) BY kibana.alert.rule.name | SORT count DESC | LIMIT 3`
      ),
    ]);

    addResults(users, nodes, edges, seen, nodes[0].id, [
      { colName: "user.name", type: "user", edgeLabel: "user" },
    ]);

    addResults(processes, nodes, edges, seen, nodes[0].id, [
      { colName: "process.name", type: "process", edgeLabel: "ran" },
    ]);

    addResults(network, nodes, edges, seen, nodes[0].id, [
      { colName: "destination.ip", type: "ip", edgeLabel: "connected to" },
    ]);

    addResults(alerts, nodes, edges, seen, nodes[0].id, [
      { colName: "kibana.alert.rule.name", type: "alert", edgeLabel: "triggered" },
    ]);

    return { nodes, edges };
  }

  private async investigateIP(
    ip: string,
    timeRange: string
  ): Promise<InvestigationResult> {
    const nodes: GraphNode[] = [
      { id: nodeId("ip", ip), type: "ip", value: ip },
    ];
    const edges: GraphEdge[] = [];
    const seen = new Set<string>([nodes[0].id]);
    const tc = buildTimeClause(timeRange);

    const [hosts, processes] = await Promise.all([
      this.safeQuery(
        `FROM logs-endpoint.events.network-* | WHERE destination.ip == "${esc(ip)}" ${tc} | STATS count=COUNT(*) BY host.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.network-* | WHERE destination.ip == "${esc(ip)}" ${tc} | STATS count=COUNT(*) BY process.name | SORT count DESC | LIMIT 3`
      ),
    ]);

    addResults(hosts, nodes, edges, seen, nodes[0].id, [
      { colName: "host.name", type: "host", edgeLabel: "from host" },
    ]);

    addResults(processes, nodes, edges, seen, nodes[0].id, [
      { colName: "process.name", type: "process", edgeLabel: "via process" },
    ]);

    return { nodes, edges };
  }

  private async investigateProcess(
    processName: string,
    timeRange: string
  ): Promise<InvestigationResult> {
    const nodes: GraphNode[] = [
      { id: nodeId("process", processName), type: "process", value: processName },
    ];
    const edges: GraphEdge[] = [];
    const seen = new Set<string>([nodes[0].id]);
    const tc = buildTimeClause(timeRange);

    const [children, parents, hosts, network] = await Promise.all([
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE process.parent.name == "${esc(processName)}" ${tc} | STATS count=COUNT(*) BY process.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE process.name == "${esc(processName)}" ${tc} | STATS count=COUNT(*) BY process.parent.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.process-* | WHERE process.name == "${esc(processName)}" ${tc} | STATS count=COUNT(*) BY host.name | SORT count DESC | LIMIT 3`
      ),
      this.safeQuery(
        `FROM logs-endpoint.events.network-* | WHERE process.name == "${esc(processName)}" ${tc} | STATS count=COUNT(*) BY destination.ip | SORT count DESC | LIMIT 3`
      ),
    ]);

    addResults(children, nodes, edges, seen, nodes[0].id, [
      { colName: "process.name", type: "process", edgeLabel: "spawned" },
    ]);

    addResults(parents, nodes, edges, seen, nodes[0].id, [
      { colName: "process.parent.name", type: "process", edgeLabel: "parent" },
    ]);

    addResults(hosts, nodes, edges, seen, nodes[0].id, [
      { colName: "host.name", type: "host", edgeLabel: "on host" },
    ]);

    addResults(network, nodes, edges, seen, nodes[0].id, [
      { colName: "destination.ip", type: "ip", edgeLabel: "connected to" },
    ]);

    return { nodes, edges };
  }

  private async safeQuery(query: string): Promise<EsqlEnvelope | null> {
    try {
      return await this.options.investigateClient.runEsql(query);
    } catch {
      return null;
    }
  }
}

function nodeId(type: string, value: string): string {
  return `${type}:${value}`;
}

function buildTimeClause(timeRange: string): string {
  const match = timeRange.match(/^now-(\d+)([dhm])$/);
  if (!match) return "";
  const val = match[1];
  const unit =
    match[2] === "d" ? "days" : match[2] === "h" ? "hours" : "minutes";
  return `AND @timestamp >= NOW() - ${val} ${unit}`;
}

function esc(s: string): string {
  return s.replace(/"/g, '\\"');
}

interface ColMapping {
  colName: string;
  type: GraphNode["type"];
  edgeLabel: string;
}

function addResults(
  result: EsqlEnvelope | null,
  nodes: GraphNode[],
  edges: GraphEdge[],
  seen: Set<string>,
  sourceId: string,
  mappings: ColMapping[]
): void {
  if (!result) return;
  for (const mapping of mappings) {
    const colIdx = result.columns.findIndex((c) => c.name === mapping.colName);
    if (colIdx === -1) continue;
    const countIdx = result.columns.findIndex((c) => c.name === "count");

    for (const row of result.values) {
      const val = row[colIdx];
      if (!val || typeof val !== "string" || val === "null") continue;

      const id = nodeId(mapping.type, val);
      if (!seen.has(id)) {
        seen.add(id);
        const count = countIdx >= 0 ? Number(row[countIdx]) || 0 : 0;
        nodes.push({
          id,
          type: mapping.type,
          value: val,
          metadata: count ? { count } : undefined,
        });
      }

      const edgeKey = `${sourceId}->${id}`;
      const reverseKey = `${id}->${sourceId}`;
      if (
        !edges.some(
          (e) =>
            `${e.source}->${e.target}` === edgeKey ||
            `${e.source}->${e.target}` === reverseKey
        )
      ) {
        edges.push({ source: sourceId, target: id, label: mapping.edgeLabel });
      }
    }
  }
}

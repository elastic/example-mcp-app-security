/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Fixtures for the Threat Hunt view.
 */

import type { EsqlResult } from "../../src/shared/types";

// ──────────────────────────────────────────────────────────────────────────
// ES|QL result
// ──────────────────────────────────────────────────────────────────────────

const NOW = new Date("2026-04-22T14:18:00.000Z");
function minutesAgo(m: number): string { return new Date(NOW.getTime() - m * 60_000).toISOString(); }

const DEFAULT_ESQL_RESULT: EsqlResult = {
  columns: [
    { name: "@timestamp", type: "date" },
    { name: "host.name", type: "keyword" },
    { name: "user.name", type: "keyword" },
    { name: "process.name", type: "keyword" },
    { name: "event.action", type: "keyword" },
    { name: "count", type: "long" },
  ],
  values: [
    [minutesAgo(6), "win-dc-01", "svc_backup", "powershell.exe", "start", 1],
    [minutesAgo(5), "win-dc-01", "svc_backup", "net.exe", "start", 1],
    [minutesAgo(18), "win-dc-01", "admin.backup", "procdump.exe", "start", 1],
    [minutesAgo(47), "lin-build-03", "ci-runner", "curl", "network-connection", 3],
    [minutesAgo(88), "win-mkt-07", "sarah.lee", "cmd.exe", "start", 2],
    [minutesAgo(120), "desk-01", "jane.doe", "schtasks.exe", "start", 1],
    [minutesAgo(120), "desk-02", "tom.vega", "schtasks.exe", "start", 1],
    [minutesAgo(120), "desk-03", "paul.chen", "schtasks.exe", "start", 1],
  ],
};

function executeEsql(args: { query: string }) {
  const q = (args.query ?? "").trim();
  if (!q) return { error: "Query is empty" };
  // Very loose syntax check — anything starting with FROM / SHOW is accepted.
  if (!/^\s*(FROM|SHOW|ROW)\b/i.test(q)) {
    return { error: "Query must start with FROM, SHOW, or ROW" };
  }
  if (/\bLIMIT\s+0\b/i.test(q)) {
    return { columns: DEFAULT_ESQL_RESULT.columns, values: [] };
  }
  return DEFAULT_ESQL_RESULT;
}

// ──────────────────────────────────────────────────────────────────────────
// Graph (investigate-entity / get-entity-detail)
// ──────────────────────────────────────────────────────────────────────────

function investigateEntity(args: { entityType: string; entityValue: string }) {
  const root = `${args.entityType}:${args.entityValue}`;
  if (args.entityType === "host") {
    return {
      nodes: [
        { id: `user:${args.entityValue}-user1`, type: "user", value: "svc_backup" },
        { id: `user:${args.entityValue}-user2`, type: "user", value: "admin.backup" },
        { id: `process:${args.entityValue}-p1`, type: "process", value: "powershell.exe" },
        { id: `process:${args.entityValue}-p2`, type: "process", value: "procdump.exe" },
        { id: `ip:${args.entityValue}-ip1`, type: "ip", value: "185.220.101.42" },
      ],
      edges: [
        { source: root, target: `user:${args.entityValue}-user1`, label: "ran-as" },
        { source: root, target: `user:${args.entityValue}-user2`, label: "ran-as" },
        { source: root, target: `process:${args.entityValue}-p1`, label: "executed" },
        { source: root, target: `process:${args.entityValue}-p2`, label: "executed" },
        { source: root, target: `ip:${args.entityValue}-ip1`, label: "connected-to" },
      ],
    };
  }
  if (args.entityType === "user") {
    return {
      nodes: [
        { id: `host:${args.entityValue}-h1`, type: "host", value: "win-dc-01" },
        { id: `host:${args.entityValue}-h2`, type: "host", value: "fs01" },
      ],
      edges: [
        { source: root, target: `host:${args.entityValue}-h1`, label: "signed-in" },
        { source: root, target: `host:${args.entityValue}-h2`, label: "accessed" },
      ],
    };
  }
  if (args.entityType === "process") {
    return {
      nodes: [
        { id: `ip:${args.entityValue}-ip1`, type: "ip", value: "185.220.101.42" },
        { id: `process:${args.entityValue}-child`, type: "process", value: "cmd.exe" },
      ],
      edges: [
        { source: root, target: `ip:${args.entityValue}-ip1`, label: "connected-to" },
        { source: root, target: `process:${args.entityValue}-child`, label: "spawned" },
      ],
    };
  }
  return { nodes: [], edges: [] };
}

function getEntityDetail(args: { entityType: string; entityValue: string }) {
  if (args.entityType === "host") {
    return {
      name: args.entityValue,
      os: { name: "Windows Server", platform: "windows", version: "2022" },
      ip: ["10.10.1.4", "10.10.2.4"],
      alertsLast24h: 14,
      riskScore: 94,
      riskLevel: "Critical",
      lastSeen: minutesAgo(2),
      topRules: [
        "Suspicious PowerShell Encoded Command",
        "Credential Access via LSASS Memory Dump",
        "Registry Persistence Mechanism",
      ],
    };
  }
  if (args.entityType === "user") {
    return {
      name: args.entityValue,
      domain: "CORP",
      alertsLast24h: 8,
      riskScore: 81,
      riskLevel: "High",
      lastSeen: minutesAgo(4),
      signInHosts: ["win-dc-01", "fs01"],
    };
  }
  if (args.entityType === "process") {
    return {
      name: args.entityValue,
      firstSeen: minutesAgo(6),
      totalExecutions: 3,
      parents: ["services.exe"],
      children: ["cmd.exe", "net.exe"],
      hashes: { sha256: "9f1b…c4e2" },
    };
  }
  if (args.entityType === "ip") {
    return {
      value: args.entityValue,
      geo: { country: "Russia", city: "St. Petersburg" },
      reputation: "Malicious (TOR exit)",
      connectionsLast24h: 6,
      relatedHosts: ["win-dc-01", "lin-build-03"],
    };
  }
  return { value: args.entityValue };
}

export default {
  "execute-esql": executeEsql,
  "investigate-entity": investigateEntity,
  "get-entity-detail": getEntityDetail,
} as Record<string, unknown | ((args: any) => unknown)>;

export const variants: Record<string, Record<string, unknown>> = {
  empty: {
    "execute-esql": { columns: DEFAULT_ESQL_RESULT.columns, values: [] },
  },
};

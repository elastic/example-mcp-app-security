/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Fixtures for the Attack Discovery view.
 */

import type { AttackDiscoveryFinding } from "../../src/shared/types";

const NOW = new Date("2026-04-22T14:18:00.000Z");
function minutesAgo(m: number): string { return new Date(NOW.getTime() - m * 60_000).toISOString(); }

const DISCOVERIES: AttackDiscoveryFinding[] = [
  {
    id: "disc-001",
    timestamp: minutesAgo(7),
    title: "Credential dump leading to domain-controller compromise",
    summaryMarkdown:
      "A multi-stage attack on **win-dc-01** began with an encoded PowerShell command by **svc_backup**, followed by an LSASS memory dump and lateral movement to the DC via stolen credentials.",
    detailsMarkdown:
      "1. **Initial execution** — `powershell.exe -EncodedCommand …` launched by services.exe.\n" +
      "2. **Credential access** — ProcDump produced a minidump of lsass.exe.\n" +
      "3. **Lateral movement** — `net use \\\\fs01\\share /user:admin` succeeded using the dumped hash.\n" +
      "4. **Persistence** — new scheduled task `BackupAgent` created.",
    mitreTactics: ["Execution", "Credential Access", "Lateral Movement", "Persistence"],
    alertIds: ["al-1001", "al-1002", "al-1006"],
    alertCount: 3,
    alertsContextCount: 3,
    riskScore: 92,
    confidence: "high",
    hosts: ["win-dc-01"],
    users: ["svc_backup", "admin.backup"],
    ruleNames: [
      "Suspicious PowerShell Encoded Command",
      "Credential Access via LSASS Memory Dump",
      "Registry Persistence Mechanism",
    ],
    signals: {
      alertDiversity: { alertCount: 3, ruleCount: 3, severities: ["critical", "critical", "high"] },
      ruleFrequency: [
        { ruleName: "Suspicious PowerShell Encoded Command", totalAlerts7d: 14, hostCount: 3 },
        { ruleName: "Credential Access via LSASS Memory Dump", totalAlerts7d: 2, hostCount: 1 },
      ],
      entityRisk: [
        { name: "win-dc-01", type: "host", riskLevel: "Critical", riskScore: 94 },
        { name: "svc_backup", type: "user", riskLevel: "High", riskScore: 81 },
      ],
    },
  },
  {
    id: "disc-002",
    timestamp: minutesAgo(35),
    title: "Phishing-initiated PowerShell bursts across marketing laptops",
    summaryMarkdown:
      "Three marketing endpoints show **WINWORD.EXE → cmd.exe → powershell.exe** chains within 45 minutes, consistent with a macro-based phishing payload.",
    detailsMarkdown:
      "The pattern repeats on win-mkt-07, win-mkt-11, and win-mkt-14. Each chain terminates with an outbound connection to the same IP.",
    mitreTactics: ["Initial Access", "Execution"],
    alertIds: ["al-1007", "al-1010"],
    alertCount: 2,
    alertsContextCount: 4,
    riskScore: 74,
    confidence: "moderate",
    hosts: ["win-mkt-07", "win-mkt-11", "win-mkt-14"],
    users: ["sarah.lee", "tom.vega", "paul.chen"],
    ruleNames: [
      "Office Application Spawned Child Process",
      "Suspicious PowerShell Encoded Command",
    ],
    signals: {
      alertDiversity: { alertCount: 4, ruleCount: 2, severities: ["high", "high", "medium", "high"] },
      ruleFrequency: [
        { ruleName: "Office Application Spawned Child Process", totalAlerts7d: 5, hostCount: 3 },
      ],
      entityRisk: [
        { name: "win-mkt-07", type: "host", riskLevel: "High", riskScore: 72 },
      ],
    },
  },
  {
    id: "disc-003",
    timestamp: minutesAgo(72),
    title: "CI runner exfiltration via TOR",
    summaryMarkdown:
      "**lin-build-03** initiated an outbound TLS session to 185.220.101.42 (known TOR exit) outside of any build window. Accompanied by failed-auth bursts and long-tail DNS queries.",
    mitreTactics: ["Command and Control", "Exfiltration"],
    alertIds: ["al-1004", "al-1005", "al-1009"],
    alertCount: 3,
    alertsContextCount: 3,
    riskScore: 68,
    confidence: "moderate",
    hosts: ["lin-build-03"],
    users: ["ci-runner"],
    ruleNames: [
      "Unusual Network Connection to Rare External Host",
      "Failed Authentication Burst",
      "DNS Tunneling Indicators",
    ],
  },
  {
    id: "disc-004",
    timestamp: minutesAgo(110),
    title: "Low-severity persistence patterns across desktops",
    summaryMarkdown:
      "Six endpoints created identical scheduled tasks (`BackupAgent`) in the same hour. Likely the same lightweight persistence mechanism on all six.",
    mitreTactics: ["Persistence"],
    alertIds: ["al-1008"],
    alertCount: 1,
    alertsContextCount: 6,
    riskScore: 41,
    confidence: "low",
    hosts: ["desk-01", "desk-02", "desk-03", "desk-04", "desk-05", "desk-06"],
    users: ["jane.doe", "sarah.lee", "tom.vega"],
    ruleNames: ["Suspicious Scheduled Task Created"],
  },
];

export default {
  "get-generation-status": () => ({
    generations: [
      {
        status: "succeeded",
        connector_id: "conn-gpt-4o",
        discoveries: DISCOVERIES.length,
        start: minutesAgo(8),
        end: minutesAgo(7),
        execution_uuid: "gen-abc-001",
        loading_message: undefined,
      },
    ],
  }),
  "list-ai-connectors": () => [
    { id: "conn-gpt-4o", name: "GPT-4o" },
    { id: "conn-claude-sonnet", name: "Claude Sonnet 4.5" },
  ],
  "poll-discoveries": () => ({ discoveries: DISCOVERIES, total: DISCOVERIES.length }),
  "assess-discovery-confidence": (args: { discoveries: string }) => {
    // View expects the same array of discoveries back, annotated with `confidence`.
    const parsed = JSON.parse(args.discoveries) as AttackDiscoveryFinding[];
    const confidences: Array<"high" | "moderate" | "low"> = ["high", "moderate", "low"];
    return parsed.map((d, i) => ({
      ...d,
      confidence: d.confidence ?? confidences[i % confidences.length],
    }));
  },
  "enrich-discovery": (args: { discovery: string }) => {
    // View reads this as a `DiscoveryDetail` ({ titleWithReplacements, summaryWithReplacements,
    // detailsWithReplacements, alerts[], entityRisk[] }).
    const d = JSON.parse(args.discovery) as AttackDiscoveryFinding;
    return {
      titleWithReplacements: d.title,
      summaryWithReplacements: d.summaryMarkdown,
      detailsWithReplacements:
        (d.detailsMarkdown ?? d.summaryMarkdown) +
        "\n\n**Enriched:** Cross-referenced with last 24h of telemetry — 2 matching sequences found on peer hosts.",
      alerts: (d.alertIds ?? []).map((id, i) => ({
        id,
        ruleName: d.ruleNames?.[i % (d.ruleNames?.length ?? 1)] ?? "Detection rule",
        severity: d.signals?.alertDiversity.severities[i % (d.signals?.alertDiversity.severities.length ?? 1)] ?? "high",
        host: d.hosts?.[i % (d.hosts?.length ?? 1)] ?? "unknown-host",
        user: d.users?.[i % (d.users?.length ?? 1)] ?? "unknown-user",
        timestamp: d.timestamp,
      })),
      entityRisk: (d.signals?.entityRisk ?? []).map((e) => ({
        name: e.name, type: e.type, level: e.riskLevel, score: e.riskScore,
      })),
    };
  },
  "approve-discoveries": (args: { findings: unknown[] }) => ({ created: args.findings?.length ?? 0 }),
  "acknowledge-discoveries": (args: { discoveryIds: string[] }) => ({ updated: args.discoveryIds?.length ?? 0 }),
} as Record<string, unknown | ((args: any) => unknown)>;

export const variants: Record<string, Record<string, unknown>> = {
  empty: {
    "poll-discoveries": { discoveries: [], total: 0 },
  },
  generating: {
    "get-generation-status": {
      generations: [{
        status: "running",
        connector_id: "conn-gpt-4o",
        discoveries: 0,
        start: minutesAgo(1),
        execution_uuid: "gen-running-001",
        loading_message: "Correlating alerts across the last hour…",
      }],
    },
    "poll-discoveries": { discoveries: [], total: 0 },
  },
};

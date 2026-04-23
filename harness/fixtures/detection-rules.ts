/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Fixtures for the Detection Rules view.
 */

import type { DetectionRule } from "../../src/shared/types";

const NOW = new Date("2026-04-22T14:18:00.000Z");
function daysAgo(d: number): string { return new Date(NOW.getTime() - d * 86_400_000).toISOString(); }

const RULES: DetectionRule[] = [
  {
    id: "rule-001", rule_id: "dr-powershell-encoded",
    name: "Suspicious PowerShell Encoded Command",
    description: "Detects powershell.exe invoked with -EncodedCommand, a common malware loader technique.",
    severity: "high", risk_score: 73, type: "query", enabled: true,
    query: "process.name:powershell.exe and process.args:-EncodedCommand",
    language: "kuery",
    index: ["logs-endpoint.events.process-*"],
    tags: ["Execution", "Windows", "Elastic", "Threat Detection"],
    threat: [{ framework: "MITRE ATT&CK", tactic: { id: "TA0002", name: "Execution", reference: "https://attack.mitre.org/tactics/TA0002" } }],
    created_at: daysAgo(180), updated_at: daysAgo(7), created_by: "elastic",
  },
  {
    id: "rule-002", rule_id: "dr-lsass-dump",
    name: "Credential Access via LSASS Memory Dump",
    description: "Detects tools like procdump, mimikatz, or comsvcs.dll producing a minidump of lsass.exe.",
    severity: "critical", risk_score: 88, type: "eql", enabled: true,
    query: "process where process.name : (\"procdump.exe\", \"procdump64.exe\") and process.args : \"lsass\"",
    language: "eql",
    index: ["logs-endpoint.events.process-*"],
    tags: ["Credential Access", "Windows", "Elastic"],
    created_at: daysAgo(220), updated_at: daysAgo(3), created_by: "elastic",
  },
  {
    id: "rule-003", rule_id: "dr-rare-host",
    name: "Unusual Network Connection to Rare External Host",
    description: "Flags outbound connections to destinations rarely seen for the source host.",
    severity: "medium", risk_score: 50, type: "machine_learning", enabled: true,
    tags: ["Network", "ML", "Elastic"], language: undefined,
    created_at: daysAgo(90), updated_at: daysAgo(30), created_by: "elastic",
  },
  {
    id: "rule-004", rule_id: "dr-failed-auth-burst",
    name: "Failed Authentication Burst",
    description: "Counts failed authentication events per user per host over a 2-minute window.",
    severity: "medium", risk_score: 47, type: "threshold", enabled: true,
    query: "event.category:authentication and event.outcome:failure",
    language: "kuery",
    index: ["logs-*", "auditbeat-*"],
    tags: ["Initial Access", "Identity", "Elastic"],
    created_at: daysAgo(300), updated_at: daysAgo(14), created_by: "elastic",
  },
  {
    id: "rule-005", rule_id: "dr-office-spawns",
    name: "Office Application Spawned Child Process",
    description: "Detects MS Office apps (WINWORD, EXCEL, POWERPNT) spawning cmd.exe, powershell.exe, or wscript.exe.",
    severity: "high", risk_score: 71, type: "eql", enabled: true,
    query: "process where process.parent.name : (\"winword.exe\", \"excel.exe\") and process.name : (\"cmd.exe\", \"powershell.exe\")",
    language: "eql",
    index: ["logs-endpoint.events.process-*"],
    tags: ["Execution", "Office", "Phishing", "Elastic"],
    created_at: daysAgo(120), updated_at: daysAgo(21), created_by: "elastic",
  },
  {
    id: "rule-006", rule_id: "dr-scheduled-task",
    name: "Suspicious Scheduled Task Created",
    description: "New scheduled tasks created with schtasks.exe or via at.exe.",
    severity: "low", risk_score: 33, type: "query", enabled: false,
    query: "process.name:schtasks.exe and process.args:/create",
    language: "kuery",
    index: ["logs-endpoint.events.process-*"],
    tags: ["Persistence", "Windows"],
    created_at: daysAgo(60), updated_at: daysAgo(2), created_by: "pmanko",
  },
  {
    id: "rule-007", rule_id: "dr-dns-tunnel",
    name: "DNS Tunneling Indicators",
    description: "High-entropy / long TXT queries to rare domains.",
    severity: "low", risk_score: 28, type: "query", enabled: true,
    query: "dns.question.type:TXT and dns.question.name:*",
    language: "kuery",
    index: ["logs-network.dns-*"],
    tags: ["Exfiltration", "Network", "DNS"],
    created_at: daysAgo(45), updated_at: daysAgo(10), created_by: "elastic",
  },
  {
    id: "rule-008", rule_id: "dr-registry-run",
    name: "Registry Persistence Mechanism",
    description: "Detects value writes under HKCU\\…\\Run and HKLM\\…\\Run.",
    severity: "high", risk_score: 70, type: "eql", enabled: true,
    query: "registry where registry.path : \"*\\\\CurrentVersion\\\\Run\\\\*\"",
    language: "eql",
    index: ["logs-endpoint.events.registry-*"],
    tags: ["Persistence", "Windows", "Elastic"],
    created_at: daysAgo(200), updated_at: daysAgo(40), created_by: "elastic",
  },
];

function findRules(args: { filter?: string }) {
  const q = (args.filter ?? "").toLowerCase();
  const filtered = q
    ? RULES.filter((r) =>
        r.name.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        (r.tags ?? []).some((t) => t.toLowerCase().includes(q)),
      )
    : RULES;
  // The view reads `data.data` and `data.total`, not `data.rules`.
  return { data: filtered, total: filtered.length };
}

const NOISY_RULES = [
  { id: "rule-004", name: "Failed Authentication Burst", alertCount: 412, lastFired: new Date(NOW.getTime() - 3 * 60_000).toISOString() },
  { id: "rule-007", name: "DNS Tunneling Indicators", alertCount: 188, lastFired: new Date(NOW.getTime() - 12 * 60_000).toISOString() },
  { id: "rule-001", name: "Suspicious PowerShell Encoded Command", alertCount: 97, lastFired: new Date(NOW.getTime() - 6 * 60_000).toISOString() },
];

export default {
  "find-rules": (args: { filter?: string }) => findRules(args),
  "get-rule": (args: { id: string }) => RULES.find((r) => r.id === args.id) ?? RULES[0],
  "toggle-rule": (_args: { id: string; enabled: boolean }) => ({ toggled: true }),
  "validate-query": (args: { query: string; language?: string }) => {
    // naive: flag obvious syntax issues
    if (!args.query || !args.query.trim()) return { valid: false, error: "Query is empty" };
    if (args.query.includes("??")) return { valid: false, error: "Unexpected token '??'" };
    return { valid: true };
  },
  "noisy-rules": () => NOISY_RULES,
} as Record<string, unknown | ((args: any) => unknown)>;

export const variants: Record<string, Record<string, unknown>> = {
  empty: {
    "find-rules": { data: [], total: 0 },
    "noisy-rules": [],
  },
};

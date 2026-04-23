/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Fixtures for the Alert Triage view.
 *
 * Each key is a tool name the view calls via `app.callServerTool(...)`.
 * The value is either a plain object (returned as-is, JSON-encoded) or a
 * function `(args) => data` for dynamic responses.
 *
 * Edit these values to change what the view renders — no server restart
 * needed, Vite will hot-reload.
 */

import type { AlertSummary, AlertContext, SecurityAlert } from "../../src/shared/types";

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

const NOW = new Date("2026-04-22T14:18:00.000Z");

function minutesAgo(m: number): string {
  return new Date(NOW.getTime() - m * 60_000).toISOString();
}

function makeAlert(partial: Partial<SecurityAlert["_source"]> & {
  _id?: string;
  rule: string;
  severity: "low" | "medium" | "high" | "critical";
  risk: number;
  reason: string;
  minutesAgo?: number;
}): SecurityAlert {
  const id = partial._id ?? `alert-${Math.random().toString(36).slice(2, 10)}`;
  const ts = minutesAgo(partial.minutesAgo ?? 15);
  return {
    _id: id,
    _index: ".alerts-security.alerts-default",
    _source: {
      "@timestamp": ts,
      "kibana.alert.rule.name": partial.rule,
      "kibana.alert.rule.uuid": `rule-${partial.rule.toLowerCase().replace(/\W+/g, "-")}`,
      "kibana.alert.severity": partial.severity,
      "kibana.alert.risk_score": partial.risk,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": partial.reason,
      "kibana.alert.rule.description": partial["kibana.alert.rule.description"],
      "kibana.alert.rule.threat": partial["kibana.alert.rule.threat"],
      host: partial.host ?? { name: "win-dc-01", os: { name: "Windows", platform: "windows" } },
      user: partial.user ?? { name: "svc_backup", domain: "CORP" },
      process: partial.process,
      file: partial.file,
      source: partial.source,
      destination: partial.destination,
    },
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Canned data
// ──────────────────────────────────────────────────────────────────────────

const ALERTS: SecurityAlert[] = [
  makeAlert({
    _id: "al-1001",
    rule: "Suspicious PowerShell Encoded Command",
    severity: "critical",
    risk: 92,
    reason: "Encoded PowerShell command executed on win-dc-01 by svc_backup. Decoded payload contacts external IP.",
    minutesAgo: 6,
    "kibana.alert.rule.threat": [{
      framework: "MITRE ATT&CK",
      tactic: { id: "TA0002", name: "Execution", reference: "https://attack.mitre.org/tactics/TA0002" },
      technique: [{ id: "T1059.001", name: "PowerShell", reference: "https://attack.mitre.org/techniques/T1059/001" }],
    }],
    process: {
      name: "powershell.exe",
      pid: 4821,
      executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      args: ["-NoProfile", "-EncodedCommand", "SQBFAFgAIAAoAE4AZQB3..."],
      parent: { name: "services.exe", pid: 680 },
    },
  }),
  makeAlert({
    _id: "al-1002",
    rule: "Credential Access via LSASS Memory Dump",
    severity: "critical",
    risk: 88,
    reason: "Process minidump of lsass.exe detected on win-dc-01. Tool: ProcDump.",
    minutesAgo: 18,
    user: { name: "admin.backup", domain: "CORP" },
    "kibana.alert.rule.threat": [{
      framework: "MITRE ATT&CK",
      tactic: { id: "TA0006", name: "Credential Access", reference: "https://attack.mitre.org/tactics/TA0006" },
      technique: [{ id: "T1003.001", name: "LSASS Memory", reference: "https://attack.mitre.org/techniques/T1003/001" }],
    }],
  }),
  makeAlert({
    _id: "al-1003",
    rule: "Malware Prevention - Trojan Detected",
    severity: "high",
    risk: 76,
    reason: "Endpoint detected trojan in payload.dll and quarantined the process.",
    minutesAgo: 34,
    host: { name: "mac-dev-12", os: { name: "macOS", platform: "darwin" } },
    user: { name: "jane.doe" },
    file: { name: "payload.dll", path: "/tmp/payload.dll", hash: { sha256: "9f1b…c4e2" } },
  }),
  makeAlert({
    _id: "al-1004",
    rule: "Unusual Network Connection to Rare External Host",
    severity: "medium",
    risk: 54,
    reason: "Outbound to IP 185.220.101.42 (country: RU) is rare for this host.",
    minutesAgo: 47,
    host: { name: "lin-build-03", os: { name: "Linux", platform: "linux" }, ip: ["10.20.3.14"] },
    user: { name: "ci-runner" },
    source: { ip: "10.20.3.14", port: 48211 },
    destination: { ip: "185.220.101.42", port: 443 },
  }),
  makeAlert({
    _id: "al-1005",
    rule: "Failed Authentication Burst",
    severity: "medium",
    risk: 48,
    reason: "27 failed SSH logins for ci-runner within 90s.",
    minutesAgo: 55,
    host: { name: "lin-build-03", os: { name: "Linux", platform: "linux" } },
    user: { name: "ci-runner" },
  }),
  makeAlert({
    _id: "al-1006",
    rule: "Registry Persistence Mechanism",
    severity: "high",
    risk: 71,
    reason: "New autorun value added to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
    minutesAgo: 62,
  }),
  makeAlert({
    _id: "al-1007",
    rule: "Office Application Spawned Child Process",
    severity: "high",
    risk: 68,
    reason: "WINWORD.EXE spawned cmd.exe on win-mkt-07.",
    minutesAgo: 88,
    host: { name: "win-mkt-07", os: { name: "Windows", platform: "windows" } },
    user: { name: "sarah.lee", domain: "CORP" },
    process: {
      name: "cmd.exe",
      pid: 9281,
      parent: { name: "WINWORD.EXE", pid: 7704 },
    },
  }),
  makeAlert({
    _id: "al-1008",
    rule: "Suspicious Scheduled Task Created",
    severity: "low",
    risk: 33,
    reason: "schtasks.exe created task 'BackupAgent' running daily.",
    minutesAgo: 120,
  }),
  makeAlert({
    _id: "al-1009",
    rule: "DNS Tunneling Indicators",
    severity: "low",
    risk: 29,
    reason: "Long repeated TXT queries to unusual subdomains.",
    minutesAgo: 150,
    host: { name: "lin-build-03", os: { name: "Linux", platform: "linux" } },
  }),
  makeAlert({
    _id: "al-1010",
    rule: "Suspicious PowerShell Encoded Command",
    severity: "high",
    risk: 74,
    reason: "Second burst of encoded PowerShell on win-mkt-07.",
    minutesAgo: 175,
    host: { name: "win-mkt-07", os: { name: "Windows", platform: "windows" } },
  }),
];

const SUMMARY: AlertSummary = {
  total: ALERTS.length,
  bySeverity: ALERTS.reduce<Record<string, number>>((acc, a) => {
    const sev = a._source["kibana.alert.severity"];
    acc[sev] = (acc[sev] ?? 0) + 1;
    return acc;
  }, {}),
  byRule: (() => {
    const m = new Map<string, number>();
    for (const a of ALERTS) {
      const r = a._source["kibana.alert.rule.name"];
      m.set(r, (m.get(r) ?? 0) + 1);
    }
    return Array.from(m, ([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  })(),
  byHost: (() => {
    const m = new Map<string, number>();
    for (const a of ALERTS) {
      const h = a._source.host?.name ?? "unknown";
      m.set(h, (m.get(h) ?? 0) + 1);
    }
    return Array.from(m, ([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  })(),
  alerts: ALERTS,
};

const CONTEXT_DEFAULT: AlertContext = {
  processEvents: [
    {
      "@timestamp": minutesAgo(6),
      process: {
        name: "powershell.exe",
        pid: 4821,
        executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        args: ["-NoProfile", "-EncodedCommand", "SQBFAFgA…"],
        parent: { pid: 680, name: "services.exe" },
      },
      event: { action: "start", category: ["process"] },
      user: { name: "svc_backup" },
    },
    {
      "@timestamp": minutesAgo(5),
      process: {
        name: "net.exe",
        pid: 5120,
        executable: "C:\\Windows\\System32\\net.exe",
        args: ["use", "\\\\fs01\\share", "/user:admin"],
        parent: { pid: 4821, name: "powershell.exe" },
      },
      event: { action: "start", category: ["process"] },
      user: { name: "svc_backup" },
    },
  ],
  networkEvents: [
    {
      "@timestamp": minutesAgo(5),
      source: { ip: "10.20.3.14", port: 48211 },
      destination: { ip: "185.220.101.42", port: 443 },
      network: { protocol: "tcp", direction: "outbound", bytes: 4821 },
      process: { name: "powershell.exe", pid: 4821 },
      event: { action: "network-connection" },
    },
  ],
  relatedAlerts: [ALERTS[1], ALERTS[5]],
};

// ──────────────────────────────────────────────────────────────────────────
// Exports
// ──────────────────────────────────────────────────────────────────────────

export default {
  "poll-alerts": () => SUMMARY,
  "get-alert-context": (_args: { alertId: string }) => CONTEXT_DEFAULT,
  "acknowledge-alert": (_args: { alertId: string }) => ({ acknowledged: true }),
  "create-case": (args: { title: string }) => ({
    id: `case-${Math.floor(Math.random() * 9000) + 1000}`,
    incremental_id: Math.floor(Math.random() * 90) + 10,
    title: args.title,
  }),
  "attach-alert-to-case": () => ({ attached: true }),
} as Record<string, unknown | ((args: any) => unknown)>;

export const variants: Record<string, Record<string, unknown>> = {
  empty: {
    "poll-alerts": {
      total: 0,
      bySeverity: {},
      byRule: [],
      byHost: [],
      alerts: [],
    },
  },
  loading: {
    "poll-alerts": async () => {
      await new Promise((r) => setTimeout(r, 60_000));
      return SUMMARY;
    },
  },
};

import { registerMockData, getMockState } from "../mock-ext-apps";
import type { AlertSummary, AlertContext, SecurityAlert } from "../../src/shared/types";

const now = new Date().toISOString();
const ago = (mins: number) => new Date(Date.now() - mins * 60000).toISOString();

function makeAlert(overrides: Partial<{ id: string; rule: string; severity: string; risk: number; host: string; user: string; status: string; mins: number; tactic: string; technique: string; process: string }>): SecurityAlert {
  const o = {
    id: "alert-1",
    rule: "Suspicious Process Execution",
    severity: "high",
    risk: 73,
    host: "web-server-01",
    user: "admin",
    status: "open",
    mins: 5,
    tactic: "Execution",
    technique: "T1059",
    process: "powershell.exe",
    ...overrides,
  };
  return {
    _id: o.id,
    _index: ".alerts-security.alerts-default",
    _source: {
      "@timestamp": ago(o.mins),
      "kibana.alert.rule.name": o.rule,
      "kibana.alert.rule.uuid": `rule-${o.id}`,
      "kibana.alert.severity": o.severity,
      "kibana.alert.risk_score": o.risk,
      "kibana.alert.workflow_status": o.status,
      "kibana.alert.reason": `${o.rule} detected on ${o.host} by user ${o.user}`,
      "kibana.alert.rule.description": `Detects ${o.rule.toLowerCase()} activity`,
      "kibana.alert.rule.threat": [
        {
          framework: "MITRE ATT&CK",
          tactic: { id: `TA00${Math.floor(Math.random() * 9) + 1}`, name: o.tactic, reference: `https://attack.mitre.org/tactics/TA0001` },
          technique: [{ id: o.technique, name: o.rule, reference: `https://attack.mitre.org/techniques/${o.technique}` }],
        },
      ],
      "kibana.alert.original_event.action": "exec",
      "kibana.alert.original_event.category": ["process"],
      host: { name: o.host, os: { name: "Windows", platform: "windows" }, ip: ["10.0.1.42"] },
      user: { name: o.user, domain: "CORP" },
      process: {
        name: o.process,
        pid: 4820 + Math.floor(Math.random() * 1000),
        executable: `C:\\Windows\\System32\\${o.process}`,
        args: [o.process, "-enc", "SQBuAHYAbwBrAGUA"],
        parent: { name: "cmd.exe", pid: 3100, executable: "C:\\Windows\\System32\\cmd.exe" },
        hash: { sha256: "a1b2c3d4e5f6" + o.id },
      },
      source: { ip: "10.0.1.42", port: 49152 },
      destination: { ip: "185.220.101.34", port: 443 },
    },
  };
}

const alerts: SecurityAlert[] = [
  makeAlert({ id: "a1", rule: "Suspicious PowerShell Execution", severity: "critical", risk: 91, host: "web-server-01", user: "admin", mins: 3, tactic: "Execution", technique: "T1059.001", process: "powershell.exe" }),
  makeAlert({ id: "a2", rule: "Unusual DNS Activity", severity: "high", risk: 73, host: "web-server-01", user: "system", mins: 5, tactic: "Command and Control", technique: "T1071.004", process: "dns.exe" }),
  makeAlert({ id: "a3", rule: "Credential Dumping via LSASS", severity: "critical", risk: 95, host: "dc-prod-01", user: "admin", mins: 8, tactic: "Credential Access", technique: "T1003.001", process: "mimikatz.exe" }),
  makeAlert({ id: "a4", rule: "Lateral Movement via PsExec", severity: "high", risk: 78, host: "db-server-02", user: "svc-backup", mins: 12, tactic: "Lateral Movement", technique: "T1021.002", process: "psexec.exe" }),
  makeAlert({ id: "a5", rule: "Ransomware File Encryption", severity: "critical", risk: 99, host: "file-server-01", user: "system", mins: 15, tactic: "Impact", technique: "T1486", process: "encrypt.exe" }),
  makeAlert({ id: "a6", rule: "Suspicious Registry Modification", severity: "medium", risk: 47, host: "workstation-14", user: "jdoe", mins: 25, tactic: "Persistence", technique: "T1547.001", process: "reg.exe" }),
  makeAlert({ id: "a7", rule: "Outbound Connection to Known C2", severity: "high", risk: 82, host: "web-server-01", user: "www-data", mins: 30, tactic: "Command and Control", technique: "T1071.001", process: "curl" }),
  makeAlert({ id: "a8", rule: "Unusual Parent-Child Process", severity: "low", risk: 21, host: "workstation-07", user: "asmith", mins: 45, tactic: "Defense Evasion", technique: "T1036", process: "svchost.exe" }),
  makeAlert({ id: "a9", rule: "Data Exfiltration via HTTP", severity: "high", risk: 85, host: "db-server-02", user: "svc-backup", mins: 50, tactic: "Exfiltration", technique: "T1048.003", process: "curl" }),
  makeAlert({ id: "a10", rule: "Scheduled Task Created", severity: "medium", risk: 45, host: "workstation-14", user: "jdoe", mins: 60, tactic: "Persistence", technique: "T1053.005", process: "schtasks.exe" }),
];

const loadedSummary: AlertSummary = {
  total: alerts.length,
  bySeverity: { critical: 3, high: 4, medium: 2, low: 1 },
  byRule: [
    { name: "Suspicious PowerShell Execution", count: 1 },
    { name: "Credential Dumping via LSASS", count: 1 },
    { name: "Ransomware File Encryption", count: 1 },
    { name: "Lateral Movement via PsExec", count: 1 },
    { name: "Data Exfiltration via HTTP", count: 1 },
    { name: "Outbound Connection to Known C2", count: 1 },
    { name: "Unusual DNS Activity", count: 1 },
    { name: "Suspicious Registry Modification", count: 1 },
    { name: "Scheduled Task Created", count: 1 },
    { name: "Unusual Parent-Child Process", count: 1 },
  ],
  byHost: [
    { name: "web-server-01", count: 3 },
    { name: "db-server-02", count: 2 },
    { name: "dc-prod-01", count: 1 },
    { name: "file-server-01", count: 1 },
    { name: "workstation-14", count: 2 },
    { name: "workstation-07", count: 1 },
  ],
  alerts,
};

const emptySummary: AlertSummary = {
  total: 0,
  bySeverity: {},
  byRule: [],
  byHost: [],
  alerts: [],
};

const alertContext: AlertContext = {
  processEvents: [
    { "@timestamp": ago(3), process: { name: "powershell.exe", pid: 4820, executable: "C:\\Windows\\System32\\powershell.exe", args: ["-enc", "SQBuAHYAbwBrAGUA"], parent: { pid: 3100, name: "cmd.exe" } }, event: { action: "exec", category: ["process"] }, user: { name: "admin" } },
    { "@timestamp": ago(3), process: { name: "cmd.exe", pid: 3100, executable: "C:\\Windows\\System32\\cmd.exe", parent: { pid: 1200, name: "explorer.exe" } }, event: { action: "exec", category: ["process"] }, user: { name: "admin" } },
    { "@timestamp": ago(4), process: { name: "whoami.exe", pid: 5001, executable: "C:\\Windows\\System32\\whoami.exe", parent: { pid: 4820, name: "powershell.exe" } }, event: { action: "exec", category: ["process"] }, user: { name: "admin" } },
    { "@timestamp": ago(4), process: { name: "net.exe", pid: 5010, executable: "C:\\Windows\\System32\\net.exe", args: ["user", "/domain"], parent: { pid: 4820, name: "powershell.exe" } }, event: { action: "exec", category: ["process"] }, user: { name: "admin" } },
  ],
  networkEvents: [
    { "@timestamp": ago(3), source: { ip: "10.0.1.42", port: 49152 }, destination: { ip: "185.220.101.34", port: 443 }, network: { protocol: "tls", direction: "outbound", bytes: 14200 }, process: { name: "powershell.exe", pid: 4820 }, event: { action: "connection_attempted" } },
    { "@timestamp": ago(5), source: { ip: "10.0.1.42", port: 53214 }, destination: { ip: "8.8.8.8", port: 53 }, network: { protocol: "dns", direction: "outbound", bytes: 128 }, process: { name: "dns.exe", pid: 1100 }, dns: { question: { name: "c2.malware-domain.com" } } },
  ],
  relatedAlerts: [alerts[1], alerts[6]],
};

const verdicts = [
  { rule: "Suspicious PowerShell Execution", classification: "Malicious", confidence: "high", summary: "Encoded PowerShell command with C2 callback — classic attack pattern", action: "Escalate", hosts: ["web-server-01"] },
  { rule: "Credential Dumping via LSASS", classification: "Malicious", confidence: "high", summary: "LSASS memory access consistent with credential harvesting", action: "Isolate host", hosts: ["dc-prod-01"] },
  { rule: "Unusual DNS Activity", classification: "Suspicious", confidence: "medium", summary: "DNS queries to known C2 infrastructure, needs further investigation", action: "Investigate", hosts: ["web-server-01"] },
  { rule: "Unusual Parent-Child Process", classification: "Benign", confidence: "low", summary: "Likely a legitimate scheduled maintenance task", action: "Close", hosts: ["workstation-07"] },
];

const states: Record<string, { toolResult: unknown; toolResponses: Record<string, unknown> }> = {
  loaded: {
    toolResult: { params: { days: 7, limit: 50 }, verdicts },
    toolResponses: {
      "poll-alerts": loadedSummary,
      "get-alert-context": alertContext,
      "acknowledge-alert": { success: true, alertId: "a1", newStatus: "acknowledged" },
    },
  },
  empty: {
    toolResult: { params: { days: 7, limit: 50 }, verdicts: [] },
    toolResponses: {
      "poll-alerts": emptySummary,
      "get-alert-context": { processEvents: [], networkEvents: [], relatedAlerts: [] },
    },
  },
  "critical-only": {
    toolResult: { params: { days: 1, severity: "critical", limit: 50 }, verdicts: verdicts.filter((v) => v.confidence === "high") },
    toolResponses: {
      "poll-alerts": {
        ...loadedSummary,
        total: 3,
        alerts: alerts.filter((a) => a._source["kibana.alert.severity"] === "critical"),
        bySeverity: { critical: 3 },
      },
      "get-alert-context": alertContext,
    },
  },
};

export function init() {
  const state = getMockState();
  const data = states[state] || states.loaded;
  registerMockData(data);
}

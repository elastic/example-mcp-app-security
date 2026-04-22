import { registerMockData, getMockState } from "../mock-ext-apps";
import type { DetectionRule } from "../../src/shared/types";

const ago = (mins: number) => new Date(Date.now() - mins * 60000).toISOString();

const rules: DetectionRule[] = [
  {
    id: "r1", rule_id: "rule-001", name: "Suspicious PowerShell Execution", description: "Detects encoded PowerShell commands commonly used in attacks",
    severity: "critical", risk_score: 91, type: "eql", enabled: true, query: 'process where process.name == "powershell.exe" and process.args : "-enc*"',
    language: "eql", index: ["logs-endpoint.events.process-*"], tags: ["ATT&CK-T1059.001", "Windows"],
    threat: [{ framework: "MITRE ATT&CK", tactic: { id: "TA0002", name: "Execution", reference: "https://attack.mitre.org/tactics/TA0002" }, technique: [{ id: "T1059.001", name: "PowerShell", reference: "https://attack.mitre.org/techniques/T1059/001" }] }],
    created_at: ago(43200), updated_at: ago(1440), created_by: "elastic",
    exceptions_list: [{ id: "exc-1", list_id: "exc-list-1", type: "detection", namespace_type: "single" }],
  },
  {
    id: "r2", rule_id: "rule-002", name: "Credential Dumping via LSASS Access", description: "Detects attempts to access LSASS process memory for credential theft",
    severity: "critical", risk_score: 95, type: "eql", enabled: true, query: 'process where process.name == "lsass.exe" and event.action == "access"',
    language: "eql", index: ["logs-endpoint.events.process-*"], tags: ["ATT&CK-T1003", "Windows", "Credential Access"],
    threat: [{ framework: "MITRE ATT&CK", tactic: { id: "TA0006", name: "Credential Access", reference: "https://attack.mitre.org/tactics/TA0006" }, technique: [{ id: "T1003.001", name: "LSASS Memory", reference: "https://attack.mitre.org/techniques/T1003/001" }] }],
    created_at: ago(43200), updated_at: ago(2880), created_by: "elastic",
  },
  {
    id: "r3", rule_id: "rule-003", name: "Outbound Connection to Known C2 Server", description: "Detects network connections to known command and control infrastructure",
    severity: "high", risk_score: 82, type: "query", enabled: true, query: 'destination.ip: ("185.220.101.34" OR "91.219.236.222" OR "45.33.32.156")',
    language: "kuery", index: ["logs-endpoint.events.network-*", "packetbeat-*"], tags: ["ATT&CK-T1071", "Network"],
    created_at: ago(30240), updated_at: ago(720), created_by: "elastic",
  },
  {
    id: "r4", rule_id: "rule-004", name: "Lateral Movement via PsExec", description: "Detects PsExec-based remote execution indicative of lateral movement",
    severity: "high", risk_score: 78, type: "eql", enabled: true, query: 'process where process.name : ("psexec.exe", "psexesvc.exe") and event.action == "exec"',
    language: "eql", index: ["logs-endpoint.events.process-*"], tags: ["ATT&CK-T1021", "Windows", "Lateral Movement"],
    created_at: ago(43200), updated_at: ago(4320), created_by: "elastic",
  },
  {
    id: "r5", rule_id: "rule-005", name: "Ransomware File Encryption Detected", description: "Detects mass file rename operations consistent with ransomware encryption",
    severity: "critical", risk_score: 99, type: "threshold", enabled: true, query: 'event.action: "rename" AND file.extension: ("locked", "encrypted", "crypt")',
    language: "kuery", index: ["logs-endpoint.events.file-*"], tags: ["ATT&CK-T1486", "Ransomware"],
    created_at: ago(20160), updated_at: ago(1440), created_by: "elastic",
  },
  {
    id: "r6", rule_id: "rule-006", name: "Suspicious Registry Run Key Modification", description: "Detects modifications to registry run keys for persistence",
    severity: "medium", risk_score: 47, type: "eql", enabled: false, query: 'registry where registry.path : "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*"',
    language: "eql", index: ["logs-endpoint.events.registry-*"], tags: ["ATT&CK-T1547", "Windows", "Persistence"],
    created_at: ago(43200), updated_at: ago(8640), created_by: "elastic",
  },
  {
    id: "r7", rule_id: "rule-007", name: "DNS Query to Suspicious TLD", description: "Detects DNS queries to suspicious top-level domains often used by malware",
    severity: "low", risk_score: 21, type: "query", enabled: true, query: 'dns.question.name: (*.xyz OR *.top OR *.buzz OR *.tk)',
    language: "kuery", index: ["packetbeat-*"], tags: ["ATT&CK-T1071.004", "DNS"],
    created_at: ago(43200), updated_at: ago(10080), created_by: "elastic",
  },
  {
    id: "r8", rule_id: "rule-008", name: "ES|QL Threat Hunt — Data Exfiltration", description: "Detects large outbound data transfers that may indicate exfiltration",
    severity: "high", risk_score: 76, type: "esql", enabled: true, query: 'FROM logs-endpoint.events.network-*\n| WHERE network.direction == "outbound" AND network.bytes > 10000000\n| STATS total_bytes = SUM(network.bytes), conn_count = COUNT(*) BY destination.ip\n| WHERE total_bytes > 50000000\n| SORT total_bytes DESC',
    language: "esql", index: ["logs-endpoint.events.network-*"], tags: ["ATT&CK-T1048", "Exfiltration", "ES|QL"],
    created_at: ago(7200), updated_at: ago(360), created_by: "analyst1",
  },
];

const noisyRulesData = {
  rules: [
    { id: "r7", name: "DNS Query to Suspicious TLD", alertCount: 342, hostCount: 28, avgDaily: 48.9 },
    { id: "r6", name: "Suspicious Registry Run Key Modification", alertCount: 156, hostCount: 12, avgDaily: 22.3 },
    { id: "r3", name: "Outbound Connection to Known C2 Server", alertCount: 89, hostCount: 5, avgDaily: 12.7 },
  ],
};

const states: Record<string, { toolResult: unknown; toolResponses: Record<string, unknown> }> = {
  loaded: {
    toolResult: { params: {} },
    toolResponses: {
      "find-rules": { total: rules.length, data: rules },
      "get-rule": rules[0],
      "toggle-rule": { ...rules[5], enabled: true },
      "validate-query": { valid: true },
      "noisy-rules": noisyRulesData,
    },
  },
  empty: {
    toolResult: { params: {} },
    toolResponses: {
      "find-rules": { total: 0, data: [] },
      "noisy-rules": { rules: [] },
    },
  },
};

export function init() {
  const state = getMockState();
  registerMockData(states[state] || states.loaded);
}

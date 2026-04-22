import { registerMockData, getMockState } from "../mock-ext-apps";
import type { AttackDiscoveryFinding } from "../../src/shared/types";

const ago = (mins: number) => new Date(Date.now() - mins * 60000).toISOString();

const discoveries: AttackDiscoveryFinding[] = [
  {
    id: "disc-1", timestamp: ago(30), title: "Multi-Stage Ransomware Attack Chain",
    summaryMarkdown: "A coordinated attack was detected targeting **web-server-01** and **file-server-01**. The attacker used {{host.name:web-server-01}} as initial access point, executed encoded PowerShell commands to establish C2 communication, then moved laterally to {{host.name:file-server-01}} where ransomware encryption was initiated. User {{user.name:admin}} credentials were compromised.",
    detailsMarkdown: "## Attack Timeline\n\n1. **Initial Access** (T-30min): Encoded PowerShell execution on web-server-01\n2. **C2 Establishment** (T-25min): Outbound TLS connection to 185.220.101.34\n3. **Credential Theft** (T-20min): LSASS memory dump on dc-prod-01\n4. **Lateral Movement** (T-15min): PsExec to file-server-01 via svc-backup\n5. **Impact** (T-10min): Mass file encryption on shared drives",
    mitreTactics: ["Initial Access", "Execution", "Command and Control", "Credential Access", "Lateral Movement", "Impact"],
    alertIds: ["a1", "a2", "a3", "a4", "a5"], alertCount: 5, alertsContextCount: 5, riskScore: 95, confidence: "high",
    hosts: ["web-server-01", "dc-prod-01", "file-server-01", "db-server-02"],
    users: ["admin", "svc-backup", "system"],
    ruleNames: ["Suspicious PowerShell Execution", "Credential Dumping via LSASS", "Ransomware File Encryption", "Lateral Movement via PsExec", "Unusual DNS Activity"],
    signals: {
      alertDiversity: { alertCount: 5, ruleCount: 5, severities: ["critical", "high"] },
      ruleFrequency: [
        { ruleName: "Suspicious PowerShell Execution", totalAlerts7d: 3, hostCount: 1 },
        { ruleName: "Ransomware File Encryption", totalAlerts7d: 1, hostCount: 1 },
      ],
      entityRisk: [
        { name: "web-server-01", type: "host", riskLevel: "Critical", riskScore: 95 },
        { name: "admin", type: "user", riskLevel: "Critical", riskScore: 92 },
        { name: "dc-prod-01", type: "host", riskLevel: "High", riskScore: 85 },
      ],
    },
  },
  {
    id: "disc-2", timestamp: ago(120), title: "Persistence via Scheduled Tasks and Registry",
    summaryMarkdown: "Low-confidence pattern of persistence mechanisms detected on {{host.name:workstation-14}} by user {{user.name:jdoe}}. Registry run key modifications and scheduled task creation observed within a short window. May be legitimate admin activity or early-stage compromise.",
    mitreTactics: ["Persistence", "Defense Evasion"],
    alertIds: ["a6", "a10"], alertCount: 2, alertsContextCount: 2, riskScore: 42, confidence: "low",
    hosts: ["workstation-14"], users: ["jdoe"],
    ruleNames: ["Suspicious Registry Modification", "Scheduled Task Created"],
    signals: {
      alertDiversity: { alertCount: 2, ruleCount: 2, severities: ["medium"] },
      ruleFrequency: [
        { ruleName: "Suspicious Registry Modification", totalAlerts7d: 156, hostCount: 12 },
        { ruleName: "Scheduled Task Created", totalAlerts7d: 89, hostCount: 15 },
      ],
      entityRisk: [
        { name: "workstation-14", type: "host", riskLevel: "Low", riskScore: 25 },
        { name: "jdoe", type: "user", riskLevel: "Low", riskScore: 18 },
      ],
    },
  },
  {
    id: "disc-3", timestamp: ago(60), title: "Data Exfiltration via HTTP from Database Server",
    summaryMarkdown: "Suspicious outbound HTTP transfers detected from {{host.name:db-server-02}} using user {{user.name:svc-backup}}. Large data volumes transferred to external IP addresses. This may indicate data exfiltration following the lateral movement observed in the ransomware attack chain.",
    mitreTactics: ["Exfiltration", "Command and Control"],
    alertIds: ["a7", "a9"], alertCount: 2, alertsContextCount: 2, riskScore: 78, confidence: "moderate",
    hosts: ["db-server-02"], users: ["svc-backup"],
    ruleNames: ["Outbound Connection to Known C2", "Data Exfiltration via HTTP"],
    signals: {
      alertDiversity: { alertCount: 2, ruleCount: 2, severities: ["high"] },
      ruleFrequency: [],
      entityRisk: [
        { name: "db-server-02", type: "host", riskLevel: "High", riskScore: 78 },
        { name: "svc-backup", type: "user", riskLevel: "High", riskScore: 72 },
      ],
    },
  },
];

const states: Record<string, { toolResult: unknown; toolResponses: Record<string, unknown> }> = {
  loaded: {
    toolResult: { discoveries },
    toolResponses: {
      "poll-discoveries": { discoveries },
      "get-generation-status": { status: "completed", progress: 100 },
      "list-ai-connectors": { connectors: [{ id: "c1", name: "OpenAI GPT-4", type: ".gen-ai" }] },
      "assess-discovery-confidence": { discoveryId: "disc-1", confidence: "high", reasoning: "Multiple correlated indicators across kill chain" },
      "enrich-discovery": discoveries[0],
      "approve-discoveries": { success: true, caseIds: ["case-1"] },
      "acknowledge-discoveries": { success: true },
    },
  },
  empty: {
    toolResult: { discoveries: [] },
    toolResponses: {
      "poll-discoveries": { discoveries: [] },
      "get-generation-status": { status: "idle" },
      "list-ai-connectors": { connectors: [] },
    },
  },
  generating: {
    toolResult: { discoveries: [] },
    toolResponses: {
      "poll-discoveries": { discoveries: [] },
      "get-generation-status": { status: "running", progress: 45 },
      "list-ai-connectors": { connectors: [{ id: "c1", name: "OpenAI GPT-4", type: ".gen-ai" }] },
    },
  },
};

export function init() {
  const state = getMockState();
  registerMockData(states[state] || states.loaded);
}

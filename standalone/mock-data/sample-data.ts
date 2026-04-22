import { registerMockData, getMockState } from "../mock-ext-apps";

const scenarios = [
  { id: "ransomware", name: "Ransomware Attack Chain", description: "Multi-stage ransomware: initial access → lateral movement → encryption", eventCount: 45, ruleCount: 5 },
  { id: "lateral-movement", name: "Lateral Movement Campaign", description: "PsExec and WMI-based lateral movement across domain", eventCount: 32, ruleCount: 3 },
  { id: "data-exfil", name: "Data Exfiltration", description: "Large outbound transfers to external IPs", eventCount: 28, ruleCount: 4 },
  { id: "phishing", name: "Phishing + Payload Delivery", description: "Email phishing with malicious attachment delivery", eventCount: 18, ruleCount: 2 },
];

const states: Record<string, { toolResult: unknown; toolResponses: Record<string, unknown> }> = {
  loaded: {
    toolResult: { scenarios },
    toolResponses: {
      "check-existing-sample-data": {
        totalDocs: 450,
        totalAlerts: 35,
        existingRules: 12,
        byScenario: {
          "ransomware-kill-chain": { events: 120, alerts: 7 },
          "windows-credential-theft": { events: 85, alerts: 5 },
          "linux-persistence": { events: 95, alerts: 6 },
        },
      },
      "generate-scenario": (args: Record<string, unknown>) => ({
        indexed: 50,
        scenario: args.scenario || "ransomware-kill-chain",
        indices: [`logs-endpoint.events.process-default`, `logs-endpoint.events.network-default`],
      }),
      "create-rules-for-scenario": (args: Record<string, unknown>) => ({
        created: 5,
        scenario: args.scenario || "ransomware-kill-chain",
      }),
      "cleanup-sample-data": { deleted: 450 },
    },
  },
  empty: {
    toolResult: { scenarios },
    toolResponses: {
      "check-existing-sample-data": { totalDocs: 0, totalAlerts: 0, existingRules: 0, byScenario: {} },
      "generate-scenario": (args: Record<string, unknown>) => ({
        indexed: 50,
        scenario: args.scenario || "ransomware-kill-chain",
        indices: [`logs-endpoint.events.process-default`],
      }),
      "create-rules-for-scenario": (args: Record<string, unknown>) => ({
        created: 5,
        scenario: args.scenario || "ransomware-kill-chain",
      }),
    },
  },
};

export function init() {
  const state = getMockState();
  registerMockData(states[state] || states.loaded);
}

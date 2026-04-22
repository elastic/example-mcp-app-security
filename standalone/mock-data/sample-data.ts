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
      "check-existing-sample-data": { exists: true, indices: ["sample-ransomware-*"], docCount: 450 },
      "generate-scenario": { success: true, scenario: "ransomware", eventsCreated: 45, indices: ["sample-ransomware-events"] },
      "create-rules-for-scenario": { success: true, rulesCreated: 5 },
      "cleanup-sample-data": { success: true, deletedIndices: ["sample-ransomware-events"], deletedRules: 5 },
    },
  },
  empty: {
    toolResult: { scenarios },
    toolResponses: {
      "check-existing-sample-data": { exists: false, indices: [], docCount: 0 },
      "generate-scenario": { success: true, scenario: "ransomware", eventsCreated: 45, indices: ["sample-ransomware-events"] },
    },
  },
};

export function init() {
  const state = getMockState();
  registerMockData(states[state] || states.loaded);
}

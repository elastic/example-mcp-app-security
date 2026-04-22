import { registerMockData, getMockState } from "../mock-ext-apps";
import type { KibanaCase } from "../../src/shared/types";

const ago = (mins: number) => new Date(Date.now() - mins * 60000).toISOString();

const cases: KibanaCase[] = [
  {
    id: "case-1", version: "v1", incremental_id: 101, title: "Ransomware Attack on File Server",
    description: "Multiple indicators of ransomware activity detected on file-server-01. Encrypted files found in shared drives. Incident response initiated.",
    status: "open", severity: "critical", tags: ["ransomware", "incident-response", "p1"],
    totalAlerts: 5, totalComment: 3, created_at: ago(120), created_by: { username: "analyst1", full_name: "Sarah Chen" }, updated_at: ago(15), connector: {}, settings: {},
  },
  {
    id: "case-2", version: "v1", incremental_id: 102, title: "Suspicious Lateral Movement — db-server-02",
    description: "PsExec-based lateral movement detected from compromised web-server-01 to db-server-02. Service account svc-backup used.",
    status: "in-progress", severity: "high", tags: ["lateral-movement", "investigation"],
    totalAlerts: 3, totalComment: 7, created_at: ago(240), created_by: { username: "analyst2", full_name: "Mike Torres" }, updated_at: ago(30), connector: {}, settings: {},
  },
  {
    id: "case-3", version: "v1", incremental_id: 103, title: "Phishing Campaign — Finance Department",
    description: "Multiple users in finance received phishing emails with malicious PDF attachments. Two users clicked links.",
    status: "in-progress", severity: "medium", tags: ["phishing", "social-engineering"],
    totalAlerts: 8, totalComment: 12, created_at: ago(1440), created_by: { username: "analyst1", full_name: "Sarah Chen" }, updated_at: ago(60), connector: {}, settings: {},
  },
  {
    id: "case-4", version: "v1", incremental_id: 104, title: "False Positive — Scheduled Maintenance Tasks",
    description: "Alerts triggered by scheduled maintenance scripts on workstation-07. Verified as benign activity.",
    status: "closed", severity: "low", tags: ["false-positive", "maintenance"],
    totalAlerts: 2, totalComment: 1, created_at: ago(4320), created_by: { username: "analyst3", full_name: "Alex Kim" }, updated_at: ago(2880), connector: {}, settings: {},
  },
  {
    id: "case-5", version: "v1", incremental_id: 105, title: "Credential Theft — Domain Controller",
    description: "LSASS memory dump detected on dc-prod-01. Attacker may have harvested domain credentials. Password reset in progress.",
    status: "open", severity: "critical", tags: ["credential-theft", "domain-controller", "p1"],
    totalAlerts: 4, totalComment: 9, created_at: ago(60), created_by: { username: "analyst2", full_name: "Mike Torres" }, updated_at: ago(10), connector: {}, settings: {},
  },
];

const caseComments = [
  { id: "c1", version: "v1", comment: "Initial triage complete. Confirmed ransomware variant is LockBit 3.0. IOCs extracted and shared with threat intel team.", created_at: ago(90), created_by: { username: "analyst1", full_name: "Sarah Chen" } },
  { id: "c2", version: "v1", comment: "File server isolated from network. Backup restoration started for affected shares.", created_at: ago(60), created_by: { username: "analyst2", full_name: "Mike Torres" } },
  { id: "c3", version: "v1", comment: "Forensic image captured. Evidence preserved for investigation.", created_at: ago(30), created_by: { username: "analyst3", full_name: "Alex Kim" } },
];

const states: Record<string, { toolResult: unknown; toolResponses: Record<string, unknown> }> = {
  loaded: {
    toolResult: { params: { status: "all" } },
    toolResponses: {
      "list-cases": { total: cases.length, cases },
      "get-case": cases[0],
      "get-case-alerts": { alerts: [] },
      "get-case-comments": { comments: caseComments },
      "create-case": cases[0],
      "update-case": { ...cases[0], status: "in-progress" },
      "add-case-comment": caseComments[0],
      "attach-alert-to-case": { success: true },
    },
  },
  empty: {
    toolResult: { params: { status: "all" } },
    toolResponses: {
      "list-cases": { total: 0, cases: [] },
      "get-case-comments": { comments: [] },
    },
  },
};

export function init() {
  const state = getMockState();
  registerMockData(states[state] || states.loaded);
}

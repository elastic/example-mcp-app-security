import { registerMockData, getMockState } from "../mock-ext-apps";

const esqlResult = {
  columns: [
    { name: "host.name", type: "keyword" },
    { name: "user.name", type: "keyword" },
    { name: "process.name", type: "keyword" },
    { name: "destination.ip", type: "ip" },
    { name: "network.bytes", type: "long" },
    { name: "@timestamp", type: "date" },
  ],
  values: [
    ["web-server-01", "admin", "powershell.exe", "185.220.101.34", 14200, new Date(Date.now() - 3 * 60000).toISOString()],
    ["web-server-01", "www-data", "curl", "91.219.236.222", 8450, new Date(Date.now() - 30 * 60000).toISOString()],
    ["db-server-02", "svc-backup", "curl", "45.33.32.156", 52000000, new Date(Date.now() - 50 * 60000).toISOString()],
    ["dc-prod-01", "admin", "mimikatz.exe", "10.0.1.42", 2048, new Date(Date.now() - 8 * 60000).toISOString()],
    ["file-server-01", "system", "encrypt.exe", null, 0, new Date(Date.now() - 15 * 60000).toISOString()],
    ["workstation-14", "jdoe", "reg.exe", null, 0, new Date(Date.now() - 25 * 60000).toISOString()],
    ["workstation-14", "jdoe", "schtasks.exe", null, 0, new Date(Date.now() - 60 * 60000).toISOString()],
    ["workstation-07", "asmith", "svchost.exe", "10.0.2.100", 1024, new Date(Date.now() - 45 * 60000).toISOString()],
  ],
};

const entityDetail = {
  name: "web-server-01",
  type: "host",
  riskScore: 95,
  riskLevel: "Critical",
  os: { name: "Windows Server 2022", platform: "windows" },
  ip: ["10.0.1.42"],
  alertCount: 3,
  processCount: 12,
  networkCount: 8,
  recentActivity: [
    { type: "alert", name: "Suspicious PowerShell Execution", timestamp: new Date(Date.now() - 3 * 60000).toISOString() },
    { type: "alert", name: "Unusual DNS Activity", timestamp: new Date(Date.now() - 5 * 60000).toISOString() },
    { type: "process", name: "powershell.exe → whoami.exe", timestamp: new Date(Date.now() - 4 * 60000).toISOString() },
    { type: "network", name: "TLS to 185.220.101.34:443", timestamp: new Date(Date.now() - 3 * 60000).toISOString() },
  ],
};

const investigateEntity = {
  entity: { name: "web-server-01", type: "host" },
  connections: [
    { name: "admin", type: "user", relation: "logged_in" },
    { name: "www-data", type: "user", relation: "logged_in" },
    { name: "185.220.101.34", type: "ip", relation: "connected_to" },
    { name: "91.219.236.222", type: "ip", relation: "connected_to" },
    { name: "powershell.exe", type: "process", relation: "executed" },
    { name: "curl", type: "process", relation: "executed" },
    { name: "dc-prod-01", type: "host", relation: "lateral_movement_to" },
  ],
};

const indices = [
  { index: ".alerts-security.alerts-default", health: "green", status: "open", docsCount: "1247", storeSize: "125.3mb" },
  { index: "logs-endpoint.events.process-default", health: "green", status: "open", docsCount: "542891", storeSize: "12.4gb" },
  { index: "logs-endpoint.events.network-default", health: "green", status: "open", docsCount: "1203847", storeSize: "28.7gb" },
  { index: "logs-endpoint.events.file-default", health: "green", status: "open", docsCount: "892341", storeSize: "18.2gb" },
];

const states: Record<string, { toolResult: unknown; toolResponses: Record<string, unknown> }> = {
  loaded: {
    toolResult: { query: 'FROM .alerts-security.alerts-default\n| WHERE kibana.alert.severity == "critical"\n| STATS count = COUNT(*) BY host.name, user.name\n| SORT count DESC\n| LIMIT 20', autoExecute: true },
    toolResponses: {
      "execute-esql": esqlResult,
      "investigate-entity": investigateEntity,
      "get-entity-detail": entityDetail,
      "list-indices": indices,
      "get-mapping": { "host.name": { type: "keyword" }, "user.name": { type: "keyword" }, "process.name": { type: "keyword" } },
    },
  },
  empty: {
    toolResult: { query: "" },
    toolResponses: {
      "execute-esql": { columns: [], values: [] },
      "list-indices": indices,
    },
  },
};

export function init() {
  const state = getMockState();
  registerMockData(states[state] || states.loaded);
}

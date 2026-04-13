import { esRequest } from "./client.js";

const TAG = "elastic-security-sample-data";

const SCENARIOS = {
  "windows-credential-theft": generateWindowsCredentialTheft,
  "aws-privilege-escalation": generateAwsPrivilegeEscalation,
  "okta-identity-takeover": generateOktaIdentityTakeover,
  "ransomware-kill-chain": generateRansomwareKillChain,
};

export type ScenarioName = keyof typeof SCENARIOS;
export const SCENARIO_NAMES = Object.keys(SCENARIOS) as ScenarioName[];

export async function generateSampleData(options: {
  scenario?: ScenarioName;
  count?: number;
}): Promise<{ indexed: number; scenario: string; indices: string[] }> {
  const { scenario, count = 50 } = options;

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
    "logs-system.auth-default",
    "logs-aws.cloudtrail-default",
    "logs-okta.system-default",
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

interface IndexedDoc {
  _index: string;
  _source: Record<string, unknown>;
}

async function bulkIndex(docs: IndexedDoc[]): Promise<{ indexed: number }> {
  if (docs.length === 0) return { indexed: 0 };

  const body = docs.flatMap((doc) => [
    { create: { _index: doc._index } },
    doc._source,
  ]);

  const result = await esRequest<{ items: Array<{ create: { _index: string; status: number; error?: unknown } }>; errors: boolean }>("/_bulk", {
    body: body.map((line) => JSON.stringify(line)).join("\n") + "\n",
    params: { refresh: "wait_for" },
  });

  const succeeded = result.items.filter((item) => item.create.status >= 200 && item.create.status < 300).length;
  if (result.errors) {
    const firstError = result.items.find((item) => item.create.error);
    throw new Error(`Bulk indexing had errors: ${succeeded}/${result.items.length} succeeded. First error: ${JSON.stringify(firstError?.create.error)}`);
  }

  return { indexed: succeeded };
}

function baseEvent(timestamp: string): Record<string, unknown> {
  return {
    "@timestamp": timestamp,
    tags: [TAG],
    ecs: { version: "8.11.0" },
  };
}

function randomIp(): string {
  return `192.0.2.${Math.floor(Math.random() * 254) + 1}`;
}

function minutesAgo(n: number): string {
  return new Date(Date.now() - n * 60 * 1000).toISOString();
}

function generateWindowsCredentialTheft(count: number): IndexedDoc[] {
  const host = { name: "WIN-ANALYST01", os: { name: "Windows", platform: "windows" } };
  const user = { name: "jsmith", domain: "CORP" };
  const docs: IndexedDoc[] = [];

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    docs.push({
      _index: "logs-endpoint.events.process-default",
      _source: {
        ...baseEvent(ts),
        host,
        user,
        event: { action: "start", category: ["process"] },
        process: {
          name: i % 5 === 0 ? "mimikatz.exe" : i % 3 === 0 ? "procdump.exe" : "cmd.exe",
          pid: 1000 + i,
          executable: `C:\\Windows\\Temp\\${i % 5 === 0 ? "mimikatz.exe" : "cmd.exe"}`,
          args: i % 5 === 0 ? ["sekurlsa::logonpasswords"] : ["/c", "whoami"],
          parent: { name: "explorer.exe", pid: 4000, executable: "C:\\Windows\\explorer.exe" },
        },
      },
    });
  }

  docs.push({
    _index: ".alerts-security.alerts-default",
    _source: {
      ...baseEvent(minutesAgo(0)),
      host,
      user,
      "kibana.alert.rule.name": "Credential Dumping via Mimikatz",
      "kibana.alert.rule.uuid": "sample-rule-001",
      "kibana.alert.severity": "critical",
      "kibana.alert.risk_score": 95,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "Mimikatz credential dumping detected on WIN-ANALYST01 by jsmith",
      "kibana.alert.rule.threat": [{
        framework: "MITRE ATT&CK",
        tactic: { id: "TA0006", name: "Credential Access", reference: "https://attack.mitre.org/tactics/TA0006/" },
        technique: [{ id: "T1003", name: "OS Credential Dumping", reference: "https://attack.mitre.org/techniques/T1003/" }],
      }],
      process: { name: "mimikatz.exe", pid: 1337, executable: "C:\\Windows\\Temp\\mimikatz.exe" },
    },
  });

  return docs;
}

function generateAwsPrivilegeEscalation(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const sourceIp = randomIp();

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const actions = ["AssumeRole", "CreateAccessKey", "AttachUserPolicy", "PutRolePolicy", "CreateRole"];
    docs.push({
      _index: "logs-aws.cloudtrail-default",
      _source: {
        ...baseEvent(ts),
        cloud: { provider: "aws", region: "us-east-1", account: { id: "123456789012" } },
        event: { action: actions[i % actions.length], category: ["iam"], outcome: "success" },
        user: { name: "compromised-user", id: "AIDA1234567890" },
        source: { ip: sourceIp },
        aws: {
          cloudtrail: {
            event_type: "AwsApiCall",
            user_identity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/compromised-user" },
          },
        },
      },
    });
  }

  docs.push({
    _index: ".alerts-security.alerts-default",
    _source: {
      ...baseEvent(minutesAgo(0)),
      "kibana.alert.rule.name": "AWS IAM Privilege Escalation",
      "kibana.alert.rule.uuid": "sample-rule-002",
      "kibana.alert.severity": "high",
      "kibana.alert.risk_score": 80,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "Suspicious IAM policy changes by compromised-user from " + sourceIp,
      "kibana.alert.rule.threat": [{
        framework: "MITRE ATT&CK",
        tactic: { id: "TA0004", name: "Privilege Escalation", reference: "https://attack.mitre.org/tactics/TA0004/" },
        technique: [{ id: "T1078", name: "Valid Accounts", reference: "https://attack.mitre.org/techniques/T1078/" }],
      }],
      user: { name: "compromised-user" },
      source: { ip: sourceIp },
    },
  });

  return docs;
}

function generateOktaIdentityTakeover(count: number): IndexedDoc[] {
  const docs: IndexedDoc[] = [];
  const attackerIp = randomIp();

  for (let i = 0; i < count; i++) {
    const ts = minutesAgo(count - i);
    const actions = [
      "user.session.start",
      "user.authentication.auth_via_mfa",
      "user.account.update_password",
      "user.mfa.factor.deactivate",
      "user.mfa.factor.activate",
    ];
    docs.push({
      _index: "logs-okta.system-default",
      _source: {
        ...baseEvent(ts),
        event: { action: actions[i % actions.length], category: ["authentication"], outcome: "success" },
        user: { name: "victim@example.com" },
        source: { ip: attackerIp },
        okta: {
          actor: { alternate_id: "victim@example.com", display_name: "Victim User" },
          outcome: { result: "SUCCESS" },
          client: { ip_address: attackerIp, user_agent: { raw_user_agent: "Mozilla/5.0" } },
        },
      },
    });
  }

  docs.push({
    _index: ".alerts-security.alerts-default",
    _source: {
      ...baseEvent(minutesAgo(0)),
      "kibana.alert.rule.name": "Okta MFA Factor Reset After Authentication",
      "kibana.alert.rule.uuid": "sample-rule-003",
      "kibana.alert.severity": "high",
      "kibana.alert.risk_score": 75,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "MFA factor deactivated and re-enrolled for victim@example.com from " + attackerIp,
      "kibana.alert.rule.threat": [{
        framework: "MITRE ATT&CK",
        tactic: { id: "TA0006", name: "Credential Access", reference: "https://attack.mitre.org/tactics/TA0006/" },
        technique: [{ id: "T1556", name: "Modify Authentication Process", reference: "https://attack.mitre.org/techniques/T1556/" }],
      }],
      user: { name: "victim@example.com" },
      source: { ip: attackerIp },
    },
  });

  return docs;
}

function generateRansomwareKillChain(count: number): IndexedDoc[] {
  const host = { name: "SRV-FILE01", os: { name: "Windows Server 2022", platform: "windows" } };
  const user = { name: "svc_backup", domain: "CORP" };
  const docs: IndexedDoc[] = [];
  const perPhase = Math.ceil(count / 4);

  for (let i = 0; i < perPhase; i++) {
    docs.push({
      _index: "logs-endpoint.events.process-default",
      _source: {
        ...baseEvent(minutesAgo(count - i)),
        host, user,
        event: { action: "start", category: ["process"] },
        process: {
          name: "powershell.exe", pid: 2000 + i,
          executable: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          args: ["-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"],
          parent: { name: "cmd.exe", pid: 1999 },
        },
      },
    });
  }

  for (let i = 0; i < perPhase; i++) {
    docs.push({
      _index: "logs-endpoint.events.network-default",
      _source: {
        ...baseEvent(minutesAgo(count - perPhase - i)),
        host, user,
        event: { action: "connection_attempted", category: ["network"] },
        source: { ip: "10.0.0.50", port: 49152 + i },
        destination: { ip: randomIp(), port: 443 },
        process: { name: "powershell.exe", pid: 2000 },
      },
    });
  }

  for (let i = 0; i < perPhase; i++) {
    docs.push({
      _index: "logs-endpoint.events.file-default",
      _source: {
        ...baseEvent(minutesAgo(count - 2 * perPhase - i)),
        host, user,
        event: { action: "modification", category: ["file"] },
        file: {
          name: `document_${i}.docx.encrypted`,
          path: `C:\\Shares\\Finance\\document_${i}.docx.encrypted`,
          extension: "encrypted",
        },
        process: { name: "svchost.exe", pid: 3000 },
      },
    });
  }

  docs.push({
    _index: ".alerts-security.alerts-default",
    _source: {
      ...baseEvent(minutesAgo(0)),
      host, user,
      "kibana.alert.rule.name": "Ransomware - Mass File Encryption",
      "kibana.alert.rule.uuid": "sample-rule-004",
      "kibana.alert.severity": "critical",
      "kibana.alert.risk_score": 99,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "Mass file encryption detected on SRV-FILE01 — ransomware kill chain in progress",
      "kibana.alert.rule.threat": [
        {
          framework: "MITRE ATT&CK",
          tactic: { id: "TA0040", name: "Impact", reference: "https://attack.mitre.org/tactics/TA0040/" },
          technique: [{ id: "T1486", name: "Data Encrypted for Impact", reference: "https://attack.mitre.org/techniques/T1486/" }],
        },
        {
          framework: "MITRE ATT&CK",
          tactic: { id: "TA0002", name: "Execution", reference: "https://attack.mitre.org/tactics/TA0002/" },
          technique: [{ id: "T1059.001", name: "PowerShell", reference: "https://attack.mitre.org/techniques/T1059/001/" }],
        },
      ],
      process: { name: "svchost.exe", pid: 3000 },
    },
  });

  return docs;
}

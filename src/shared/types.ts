export interface ElasticConfig {
  elasticsearchUrl: string;
  elasticsearchApiKey: string;
  kibanaUrl: string;
  kibanaApiKey: string;
}

export interface SecurityAlert {
  _id: string;
  _index: string;
  _source: {
    "@timestamp": string;
    "kibana.alert.rule.name": string;
    "kibana.alert.rule.uuid": string;
    "kibana.alert.severity": string;
    "kibana.alert.risk_score": number;
    "kibana.alert.workflow_status": string;
    "kibana.alert.reason": string;
    "kibana.alert.rule.description"?: string;
    "kibana.alert.rule.threat"?: MitreThreat[];
    "kibana.alert.original_event.action"?: string;
    "kibana.alert.original_event.category"?: string[];
    host?: {
      name?: string;
      os?: { name?: string; platform?: string };
      ip?: string[];
    };
    user?: { name?: string; domain?: string };
    process?: {
      name?: string;
      pid?: number;
      executable?: string;
      args?: string[];
      parent?: {
        name?: string;
        pid?: number;
        executable?: string;
      };
      hash?: { sha256?: string; md5?: string };
    };
    file?: {
      name?: string;
      path?: string;
      hash?: { sha256?: string; md5?: string };
    };
    source?: { ip?: string; port?: number };
    destination?: { ip?: string; port?: number };
    agent?: { id?: string; type?: string };
    [key: string]: unknown;
  };
}

export interface MitreThreat {
  framework: string;
  tactic: { id: string; name: string; reference: string };
  technique?: { id: string; name: string; reference: string; subtechnique?: { id: string; name: string; reference: string }[] }[];
}

export interface AlertSummary {
  total: number;
  bySeverity: Record<string, number>;
  byRule: { name: string; count: number }[];
  byHost: { name: string; count: number }[];
  alerts: SecurityAlert[];
}

export interface ProcessEvent {
  "@timestamp": string;
  process: {
    name?: string;
    pid?: number;
    executable?: string;
    args?: string[];
    parent?: { pid?: number; name?: string; executable?: string };
  };
  event: { action?: string; category?: string[] };
  user?: { name?: string };
}

export interface NetworkEvent {
  "@timestamp": string;
  source?: { ip?: string; port?: number };
  destination?: { ip?: string; port?: number };
  network?: { protocol?: string; direction?: string; bytes?: number };
  process?: { name?: string; pid?: number };
  event?: { action?: string };
  dns?: { question?: { name?: string } };
}

export interface AlertContext {
  processEvents: ProcessEvent[];
  networkEvents: NetworkEvent[];
  relatedAlerts: SecurityAlert[];
}

export interface KibanaCase {
  id: string;
  version: string;
  title: string;
  description: string;
  status: "open" | "in-progress" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  tags: string[];
  totalAlerts: number;
  totalComment: number;
  created_at: string;
  created_by: { username: string; full_name?: string };
  updated_at: string;
  connector: unknown;
  settings: unknown;
}

export interface DetectionRule {
  id: string;
  rule_id: string;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  risk_score: number;
  type: string;
  enabled: boolean;
  query?: string;
  language?: string;
  index?: string[];
  threat?: MitreThreat[];
  tags?: string[];
  created_at: string;
  updated_at: string;
  created_by: string;
  exceptions_list?: { id: string; list_id: string; type: string; namespace_type: string }[];
}

export interface RuleException {
  id: string;
  item_id: string;
  name: string;
  description?: string;
  entries: { field: string; operator: string; type: string; value: string | string[] }[];
  created_at: string;
}

export interface EsqlResult {
  columns: { name: string; type: string }[];
  values: unknown[][];
}

export interface IndexInfo {
  index: string;
  health: string;
  status: string;
  docsCount: string;
  storeSize: string;
}

export interface FieldMapping {
  [field: string]: { type: string; fields?: Record<string, { type: string }> };
}

export interface AttackDiscoveryFinding {
  id: string;
  timestamp: string;
  title: string;
  summaryMarkdown: string;
  detailsMarkdown?: string;
  mitreTactics: string[];
  alertIds: string[];
  alertCount: number;
  alertsContextCount: number;
  riskScore: number;
  confidence?: "high" | "moderate" | "low";
  hosts?: string[];
  users?: string[];
  ruleNames?: string[];
  signals?: {
    alertDiversity: { alertCount: number; ruleCount: number; severities: string[] };
    ruleFrequency: { ruleName: string; totalAlerts7d: number; hostCount: number }[];
    entityRisk: { name: string; type: string; riskLevel: string; riskScore: number }[];
  };
}

export interface DiscoveryDetail {
  titleWithReplacements: string;
  summaryWithReplacements: string;
  detailsWithReplacements: string;
  alerts: { id: string; ruleName: string; severity: string; host: string; user: string; timestamp: string; details?: Record<string, string> }[];
  entityRisk: { name: string; type: string; level: string; score: number }[];
}

export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITY_COLORS: Record<Severity, string> = {
  low: "#54b399",
  medium: "#d6bf57",
  high: "#da8b45",
  critical: "#e7664c",
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

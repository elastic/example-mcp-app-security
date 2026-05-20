/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  AttackDiscoveryFinding,
} from "./types.js";
import { VIEW_IDS, type ViewId } from "./analytics-events.js";
import { extractToolText } from "./extract-tool-text.js";

export const MCP_APP_BOOTSTRAP_KIND = "mcp_app_bootstrap";

export interface AlertTriageVerdict {
  readonly rule: string;
  readonly classification: "benign" | "suspicious" | "malicious";
  readonly confidence: "low" | "medium" | "high";
  readonly summary: string;
  readonly action: string;
  readonly hosts?: readonly string[];
}

export interface AlertTriageBootstrapPayload {
  readonly summary: {
    readonly total: number;
    readonly bySeverity: Record<string, number>;
    readonly byRule: readonly { readonly name: string; readonly count: number }[];
    readonly byHost: readonly { readonly name: string; readonly count: number }[];
    readonly alerts: readonly {
      readonly id: string;
      readonly rule?: string;
      readonly severity?: string;
      readonly risk_score?: number;
      readonly reason?: string;
      readonly host?: string;
      readonly user?: string;
      readonly process?: string;
      readonly executable?: string;
      readonly parent_process?: string;
      readonly file?: string;
      readonly source_ip?: string;
      readonly dest_ip?: string;
      readonly timestamp?: string;
      readonly mitre?: readonly {
        readonly tactic: string;
        readonly techniques: readonly string[];
      }[];
    }[];
  };
  readonly params: {
    readonly days: number;
    readonly severity?: string;
    readonly limit: number;
    readonly query?: string;
  };
  readonly verdicts: readonly AlertTriageVerdict[];
}

export interface CaseManagementBootstrapPayload {
  readonly total: number;
  readonly cases: readonly {
    readonly id: string;
    readonly title: string;
    readonly status: string;
    readonly severity: string;
    readonly totalAlerts?: number;
    readonly totalComment?: number;
    readonly tags?: readonly string[];
    readonly description?: string;
    readonly created_at?: string;
    readonly updated_at?: string;
    readonly created_by?: string;
  }[];
  readonly params: {
    readonly status?: string;
    readonly severity?: string;
    readonly search?: string;
  };
}

export interface DetectionRulesBootstrapPayload {
  readonly total: number;
  readonly rules: readonly {
    readonly id: string;
    readonly name: string;
    readonly type?: string;
    readonly severity?: string;
    readonly enabled?: boolean;
    readonly risk_score?: number;
    readonly description?: string;
    readonly query?: string;
    readonly language?: string;
    readonly tags?: readonly string[];
    readonly threat?: readonly {
      readonly tactic?: string;
      readonly techniques: readonly string[];
    }[];
  }[];
  readonly params: {
    readonly filter?: string;
    readonly page?: number;
    readonly perPage?: number;
  };
}

export interface AttackDiscoveryBootstrapPayload {
  readonly total: number;
  readonly discoveries: readonly (Pick<
    AttackDiscoveryFinding,
    | "id"
    | "title"
    | "summaryMarkdown"
    | "detailsMarkdown"
    | "mitreTactics"
    | "alertIds"
    | "alertCount"
    | "alertsContextCount"
    | "riskScore"
    | "timestamp"
    | "confidence"
    | "hosts"
    | "users"
    | "ruleNames"
    | "signals"
  >)[];
  readonly params: {
    readonly days: number;
    readonly limit: number;
  };
}

export interface SampleDataExistingData {
  readonly totalDocs: number;
  readonly totalAlerts: number;
  readonly existingRules: number;
  readonly byScenario: Record<string, { readonly events: number; readonly alerts: number }>;
}

export interface SampleDataBootstrapPayload {
  readonly scenarios: readonly string[];
  readonly existingData: SampleDataExistingData;
}

export interface ThreatHuntEntityRef {
  readonly type: "user" | "host" | "ip" | "process";
  readonly value: string;
}

export interface ThreatHuntBootstrapPayload {
  readonly indexCount: number;
  readonly indices: readonly string[];
  readonly params: {
    readonly query?: string;
    readonly description?: string;
    readonly entity?: ThreatHuntEntityRef;
  };
  readonly queryResult?: {
    readonly columns: readonly string[];
    readonly rows: readonly (readonly (string | number | boolean | null)[])[];
    readonly rowCount: number;
  };
  readonly queryError?: string;
  readonly entityGraph?: {
    readonly nodeCount: number;
    readonly edgeCount: number;
  };
}

export interface ViewBootstrapPayloads {
  "alert-triage": AlertTriageBootstrapPayload;
  "attack-discovery": AttackDiscoveryBootstrapPayload;
  "case-management": CaseManagementBootstrapPayload;
  "detection-rules": DetectionRulesBootstrapPayload;
  "sample-data": SampleDataBootstrapPayload;
  "threat-hunt": ThreatHuntBootstrapPayload;
}

export interface McpAppBootstrapEnvelope<V extends ViewId = ViewId> {
  readonly kind: typeof MCP_APP_BOOTSTRAP_KIND;
  readonly viewId: V;
  readonly payload: ViewBootstrapPayloads[V];
}

export interface McpAppBootstrapIdleState {
  readonly status: "idle";
}

export interface McpAppBootstrapErrorState {
  readonly status: "error";
  readonly reason: string;
  readonly rawText?: string;
}

export interface McpAppBootstrapReadyState {
  readonly status: "ready";
  readonly envelope: McpAppBootstrapEnvelope;
}

export type McpAppBootstrapState =
  | McpAppBootstrapIdleState
  | McpAppBootstrapErrorState
  | McpAppBootstrapReadyState;

export type InspectBootstrapResult =
  | { readonly status: "not_bootstrap" }
  | McpAppBootstrapErrorState
  | McpAppBootstrapReadyState;

export function createMcpAppBootstrap<V extends ViewId>(
  viewId: V,
  payload: ViewBootstrapPayloads[V],
): McpAppBootstrapEnvelope<V> {
  return {
    kind: MCP_APP_BOOTSTRAP_KIND,
    viewId,
    payload,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isViewId(value: unknown): value is ViewId {
  return typeof value === "string" && VIEW_IDS.includes(value as ViewId);
}

export function inspectMcpAppBootstrapResult(result: unknown): InspectBootstrapResult {
  const text = extractToolText(result);
  if (!text) {
    return { status: "not_bootstrap" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: "not_bootstrap" };
  }

  if (!isRecord(parsed) || parsed.kind !== MCP_APP_BOOTSTRAP_KIND) {
    return { status: "not_bootstrap" };
  }

  if (!isViewId(parsed.viewId)) {
    return {
      status: "error",
      reason: "Bootstrap payload is missing a valid viewId.",
      rawText: text,
    };
  }

  if (!("payload" in parsed)) {
    return {
      status: "error",
      reason: `Bootstrap payload for ${parsed.viewId} is missing its payload body.`,
      rawText: text,
    };
  }

  return {
    status: "ready",
    envelope: parsed as unknown as McpAppBootstrapEnvelope,
  };
}

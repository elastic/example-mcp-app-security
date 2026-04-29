/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  fetchAlerts,
  acknowledgeAlert,
} from "../../src/elastic/alerts.js";
import {
  listCases,
  getCase,
  createCase,
  updateCase,
  addComment,
  attachAlert,
} from "../../src/elastic/cases.js";
import {
  findRules,
  getRule,
  createRule,
  patchRule,
  noisyRules,
} from "../../src/elastic/rules.js";
import {
  assessConfidence,
  fetchDiscoveries,
  getDiscoveryDetail,
  listAIConnectors,
  type AttackDiscovery,
} from "../../src/elastic/attack-discovery.js";
import { esRequest } from "../../src/elastic/client.js";
import { executeEsql } from "../../src/elastic/esql.js";
import { listIndices } from "../../src/elastic/indices.js";
import {
  checkExistingData,
  generateSampleData,
} from "../../src/elastic/sample-data.js";

// The app currently targets the "default" Kibana space, so role definitions
// hard-code the resolved index/resource names rather than the <space-id>
// placeholders used in docs/permissions.md.
const SPACE = "default";
const KIBANA_RESOURCE = `space:${SPACE}`;

export interface RoleDescriptor {
  cluster: string[];
  indices: Array<{
    names: string[];
    privileges: string[];
  }>;
  applications: Array<{
    application: string;
    privileges: string[];
    resources: string[];
  }>;
}

const DATA_INDICES = [
  `.alerts-security.alerts-${SPACE}`,
  `.alerts-security.attack.discovery.alerts-${SPACE}`,
  `.adhoc.alerts-security.attack.discovery.alerts-${SPACE}`,
  // Backing indices for the alert and attack-discovery data streams.
  // `_update_by_query` and `_delete_by_query` dispatch writes directly
  // to backing indices (used by acknowledgeAlerts, acknowledgeDiscoveries,
  // and cleanupSampleData), so the role needs explicit privileges here
  // — granting them on the data stream alone is not sufficient.
  `.internal.alerts-security.alerts-${SPACE}-*`,
  `.internal.alerts-security.attack.discovery.alerts-${SPACE}-*`,
  `.internal.adhoc.alerts-security.attack.discovery.alerts-${SPACE}-*`,
  "logs-*",
  "risk-score.risk-score-latest-*",
];

export const fullRole: RoleDescriptor = {
  cluster: ["monitor"],
  indices: [
    {
      names: DATA_INDICES,
      // Index-level `monitor` is required by `_cat/indices/<pattern>`
      // (used by Threat Hunt's listIndices) — that endpoint dispatches
      // both `indices:monitor/stats` and `indices:monitor/settings/get`,
      // which only the index-level `monitor` privilege covers in full.
      // The cluster-level `monitor` above is a separate thing and is
      // not sufficient on its own.
      privileges: ["read", "write", "monitor"],
    },
  ],
  applications: [
    {
      application: "kibana-.kibana",
      privileges: [
        "feature_siemV5.all",
        "feature_securitySolutionCasesV3.all",
        "feature_securitySolutionTimeline.all",
        "feature_securitySolutionNotes.all",
        "feature_securitySolutionRulesV4.all",
        "feature_securitySolutionAlertsV1.all",
        "feature_securitySolutionAssistant.all",
        "feature_securitySolutionAttackDiscovery.all",
        "feature_actions.all",
      ],
      resources: [KIBANA_RESOURCE],
    },
  ],
};

export const readonlyRole: RoleDescriptor = {
  cluster: ["monitor"],
  indices: [
    {
      names: DATA_INDICES,
      privileges: ["read", "monitor"],
    },
  ],
  applications: [
    {
      application: "kibana-.kibana",
      privileges: [
        "feature_siemV5.read",
        "feature_securitySolutionCasesV3.read",
        "feature_securitySolutionTimeline.read",
        "feature_securitySolutionNotes.read",
        "feature_securitySolutionRulesV4.read",
        "feature_securitySolutionAlertsV1.read",
        "feature_actions.read",
      ],
      resources: [KIBANA_RESOURCE],
    },
  ],
};

export type AssertedRoleName =
  | "full"
  | "readonly"
  | "quickstart_full"
  | "quickstart_readonly";
export type RoleName = AssertedRoleName;

/**
 * Custom-role descriptors for the asserted "Advanced" path. These
 * roles are self-contained — they include cluster, index, and Kibana
 * feature privileges in a single role.
 */
export const ROLE_DESCRIPTORS: Record<"full" | "readonly", RoleDescriptor> = {
  full: fullRole,
  readonly: readonlyRole,
};

/**
 * The assertion profile for each asserted role. Quickstart variants
 * (`quickstart_full` / `quickstart_readonly`) are expected to exhibit
 * the same per-op outcomes as their custom-role counterparts (`full` /
 * `readonly`), so we look up the same `expect` map under one key.
 */
export type AssertedExpectationProfile = "full" | "readonly";
export const ASSERTED_EXPECTATION_PROFILE: Record<
  AssertedRoleName,
  AssertedExpectationProfile
> = {
  full: "full",
  readonly: "readonly",
  quickstart_full: "full",
  quickstart_readonly: "readonly",
};

/**
 * Quickstart path: built-in Kibana role paired with a small companion
 * role that grants only the index privileges the built-in lacks. This
 * matches what `docs/permissions.md` recommends to end users.
 *
 * The companion role intentionally has no cluster, Kibana-feature, or
 * application privileges — those come from the built-in. If a future
 * Kibana version stops shipping cluster `monitor` in `editor`/`viewer`,
 * the matrix run will surface the regression as a `listIndices` (or
 * similar) failure.
 */
export const QUICKSTART_BUILTINS: Record<
  "quickstart_full" | "quickstart_readonly",
  "editor" | "viewer"
> = {
  quickstart_full: "editor",
  quickstart_readonly: "viewer",
};

export const QUICKSTART_COMPANION_DESCRIPTORS: Record<
  "quickstart_full" | "quickstart_readonly",
  RoleDescriptor
> = {
  // Cluster-level `monitor` is required by `_cat/indices/<pattern>`
  // (Threat Hunt's listIndices). Neither `editor` nor `viewer` grants
  // it on a stateful 9.5 cluster, so it has to come from the companion.
  quickstart_full: {
    cluster: ["monitor"],
    indices: [
      {
        names: DATA_INDICES,
        privileges: ["read", "write", "monitor"],
      },
    ],
    applications: [],
  },
  quickstart_readonly: {
    cluster: ["monitor"],
    indices: [
      {
        names: DATA_INDICES,
        privileges: ["read", "monitor"],
      },
    ],
    applications: [],
  },
};

/** Any role identity the runner may exercise. */
export type AnyRoleName = AssertedRoleName;

export type OperationGroup =
  | "alerts"
  | "cases"
  | "rules"
  | "attack-discovery"
  | "threat-hunt"
  | "sample-data";

export type Expectation = "ok" | "403";

/** Outcome bucket for a single operation run. */
export type RunOutcome = "pass" | "403" | "404" | "other" | "skipped";

export interface SeedFixtures {
  alertId: string;
  alertIndex: string;
  alertRuleId: string;
  alertRuleName: string;
  caseId: string;
  ruleId?: string;
  discoveryId?: string;
  /** Per-run unique suffix used for case titles, rule names, etc. */
  suffix: string;
}

export interface OperationCheck {
  /** Human-readable name for the report. */
  name: string;
  /** Which `src/elastic/*` module/function group this belongs to. */
  group: OperationGroup;
  /**
   * Function that performs the operation. Receives the seed fixtures and
   * the role being tested (asserted or built-in). Throws on API failure.
   */
  run: (fixtures: SeedFixtures, role: AnyRoleName) => Promise<unknown>;
  /**
   * Per-role expectation, keyed by assertion profile (`full` or
   * `readonly`). "ok" = call must succeed. "403" = call must throw
   * with a message containing "403" (Kibana sometimes returns 401 for
   * forbidden actions; that's also accepted). Only consulted for
   * asserted roles (`full`, `readonly`, `quickstart_full`,
   * `quickstart_readonly`) via `ASSERTED_EXPECTATION_PROFILE`;
   * built-in runs record observed outcomes only.
   */
  expect: Record<AssertedExpectationProfile, Expectation>;
  /**
   * If set, returning a falsy value from the resolver marks the check as
   * "skipped" instead of running it. Used for ops that need an optional
   * fixture (e.g. attack-discovery write tests need a discoveryId).
   */
  skipUnless?: (fixtures: SeedFixtures, role: AnyRoleName) => unknown;
}

export interface CheckResult {
  check: OperationCheck;
  role: RoleName;
  outcome: "pass" | "fail" | "skipped";
  detail: string;
}

function synthDiscovery(f: SeedFixtures): AttackDiscovery {
  return {
    id: f.discoveryId!,
    timestamp: new Date().toISOString(),
    executionUuid: "",
    title: "",
    summaryMarkdown: "",
    detailsMarkdown: "",
    mitreTactics: [],
    alertIds: [f.alertId],
    alertsContextCount: 1,
    riskScore: 50,
  };
}

function ruleBody(name: string): Record<string, unknown> {
  return {
    type: "query",
    name,
    description: "Permissions test rule (safe to delete)",
    severity: "low",
    risk_score: 1,
    query: "*:*",
    language: "kuery",
    index: ["logs-*"],
    enabled: false,
    from: "now-1d",
    to: "now",
    interval: "1h",
    tags: ["mcp-app-test"],
    threat: [],
  };
}

export const operationChecks: OperationCheck[] = [
  // ─── alerts ────────────────────────────────────────────────────────────
  {
    name: "fetchAlerts",
    group: "alerts",
    run: async () => fetchAlerts({ days: 30, limit: 1 }),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "acknowledgeAlert",
    group: "alerts",
    run: async (f) => acknowledgeAlert(f.alertId),
    expect: { full: "ok", readonly: "403" },
  },

  // ─── cases ─────────────────────────────────────────────────────────────
  {
    name: "listCases",
    group: "cases",
    run: async () => listCases({ perPage: 1 }),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "getCase",
    group: "cases",
    run: async (f) => getCase(f.caseId),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "createCase",
    group: "cases",
    run: async (f, role) =>
      createCase({
        title: `mcp-app-test ${role} ${f.suffix} ${Date.now()}`,
        description: "Permissions test case (safe to delete)",
        tags: ["mcp-app-test"],
      }),
    expect: { full: "ok", readonly: "403" },
  },
  {
    // Toggles severity between "low" and "medium" so the PATCH always
    // makes a real change (Kibana rejects no-op updates with 406). The
    // toggle leaves the field in a deterministic state regardless of
    // starting value, so re-runs don't drift.
    name: "updateCase",
    group: "cases",
    run: async (f) => {
      const current = await getCase(f.caseId);
      const next = current.severity === "low" ? "medium" : "low";
      return updateCase(f.caseId, current.version, { severity: next });
    },
    expect: { full: "ok", readonly: "403" },
  },
  {
    name: "addComment",
    group: "cases",
    run: async (f) => addComment(f.caseId, "mcp-app-test comment"),
    expect: { full: "ok", readonly: "403" },
  },
  {
    name: "attachAlert",
    group: "cases",
    run: async (f) =>
      attachAlert(f.caseId, f.alertId, f.alertIndex, f.alertRuleId, f.alertRuleName),
    expect: { full: "ok", readonly: "403" },
  },

  // ─── rules ─────────────────────────────────────────────────────────────
  {
    name: "findRules",
    group: "rules",
    run: async () => findRules({ perPage: 1 }),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "noisyRules",
    group: "rules",
    run: async () => noisyRules({ days: 30, limit: 5 }),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "createRule",
    group: "rules",
    run: async (f, role) =>
      createRule(ruleBody(`mcp-app-test ${role} ${f.suffix} ${Date.now()}`)),
    expect: { full: "ok", readonly: "403" },
  },
  {
    // Non-destructive: re-patches the rule with its current `enabled`
    // value. The PATCH call still exercises the write privilege (succeeds
    // for `full`, 403s for `readonly`) without mutating state. getRule
    // succeeds for both roles, so the 403 in the readonly path comes
    // strictly from patchRule.
    name: "patchRule",
    group: "rules",
    skipUnless: (f) => f.ruleId,
    run: async (f) => {
      const rule = await getRule(f.ruleId!);
      return patchRule(f.ruleId!, { enabled: rule.enabled });
    },
    expect: { full: "ok", readonly: "403" },
  },

  // ─── attack-discovery ──────────────────────────────────────────────────
  {
    name: "fetchDiscoveries",
    group: "attack-discovery",
    run: async () => fetchDiscoveries({ days: 30, limit: 5 }),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "listAIConnectors",
    group: "attack-discovery",
    run: async () => listAIConnectors(),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    // Synthesizes an AttackDiscovery from the seeded discoveryId and a
    // real alertId so the inner ES|QL queries actually run (the helper
    // returns early when alertIds is empty). This drives reads against
    // .alerts-security.alerts-* and risk-score.risk-score-latest-*.
    name: "assessConfidence",
    group: "attack-discovery",
    skipUnless: (f) => f.discoveryId,
    run: async (f) => assessConfidence([synthDiscovery(f)]),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "getDiscoveryDetail",
    group: "attack-discovery",
    skipUnless: (f) => f.discoveryId,
    run: async (f) => getDiscoveryDetail(synthDiscovery(f)),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    // Bypasses the production helper (acknowledgeDiscoveries) which
    // silently catches per-index errors — a 403 there returns
    // `updated: 0` instead of throwing, so it can't drive a privilege
    // assertion. Calling _update_by_query directly lets the 403
    // propagate, which is what we want here.
    name: "acknowledgeDiscoveries",
    group: "attack-discovery",
    skipUnless: (f) => f.discoveryId,
    run: async (f) =>
      esRequest(
        `/.alerts-security.attack.discovery.alerts-${SPACE}/_update_by_query`,
        {
          method: "POST",
          body: {
            query: { ids: { values: [f.discoveryId!] } },
            script: {
              source: 'ctx._source["kibana.alert.workflow_status"] = "acknowledged"',
              lang: "painless",
            },
          },
        }
      ),
    expect: { full: "ok", readonly: "403" },
  },

  // ─── threat-hunt ───────────────────────────────────────────────────────
  {
    name: "executeEsql",
    group: "threat-hunt",
    run: async () => executeEsql("FROM logs-* | LIMIT 1"),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "listIndices",
    group: "threat-hunt",
    run: async () => listIndices("logs-*"),
    expect: { full: "ok", readonly: "ok" },
  },

  // ─── sample-data ───────────────────────────────────────────────────────
  {
    name: "checkExistingData",
    group: "sample-data",
    run: async () => checkExistingData(),
    expect: { full: "ok", readonly: "ok" },
  },
  {
    name: "generateSampleData",
    group: "sample-data",
    run: async () => generateSampleData({ count: 1 }),
    expect: { full: "ok", readonly: "403" },
  },
];

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import "dotenv/config";
import crypto from "node:crypto";

import type { ClusterCredentials } from "../../src/elastic/credential-client/index.js";
import {
  ASSERTED_EXPECTATION_PROFILE,
  QUICKSTART_BUILTINS,
  QUICKSTART_COMPANION_DESCRIPTORS,
  ROLE_DESCRIPTORS,
  SERVERLESS_BUILTINS,
  operationChecks,
  type AnyRoleName,
  type AssertedRoleName,
  type CheckResult,
  type OperationCheck,
  type OperationGroup,
  type RoleName,
  type RunOutcome,
  type SeedFixtures,
  type ServerlessRoleName,
} from "./roles.js";
import {
  bootstrapAdminApiKey,
  grantApiKeyForUser,
  createApiKey,
  createRole,
  createUser,
  deleteApiKey,
  deleteRole,
  deleteUser,
  hasPrivileges,
  roleExists,
  listApiKeysByPrefix,
  listRolesByPrefix,
  listUsersByPrefix,
  type CreatedApiKey,
} from "./elastic-admin.js";
import { buildServices, type Services } from "./services.js";

const TEST_TAG = "mcp-app-test";
const TEST_RESOURCE_PREFIX = "mcp-app-test-";
const ADMIN_CLUSTER_NAME = "test-permissions-admin";
const SCOPED_CLUSTER_NAME = "test-permissions-scoped";

type DeploymentMode = "stateful" | "serverless";

interface CliOptions {
  roles: RoleName[];
  mode: DeploymentMode;
  cleanupStale: boolean;
  cleanup: boolean;
  verbose: boolean;
}

interface AdminConfig {
  elasticsearchUrl: string;
  /**
   * Bootstrapped admin API key (encoded). Created on startup via Basic
   * auth so we can authenticate ES + Kibana requests through the standard
   * `createEsClient` / `createKibanaClient` factories (both expect an
   * `ApiKey` header).
   */
  elasticsearchApiKey: string;
  /** Kept around for createApiKey calls (which require Basic auth). */
  basicAuth: { username: string; password: string };
  kibanaUrl: string;
}

interface RoleArtifacts {
  role: "full" | "readonly";
  roleName: string;
  apiKey: CreatedApiKey;
}

type QuickstartRoleName = "quickstart_full" | "quickstart_readonly";

interface QuickstartArtifacts {
  role: QuickstartRoleName;
  companionRoleName: string;
  username: string;
  apiKey: CreatedApiKey;
}

interface UnavailableQuickstart {
  role: QuickstartRoleName;
  reason: string;
}

const SYM_OK = "✓";
const SYM_FAIL = "✗";
const SYM_SKIP = "→";

const GROUP_ORDER: OperationGroup[] = [
  "alerts",
  "cases",
  "rules",
  "attack-discovery",
  "threat-hunt",
  "sample-data",
];

const ALL_ASSERTED_ROLES: AssertedRoleName[] = [
  "full",
  "readonly",
  "quickstart_full",
  "quickstart_readonly",
];

const ALL_SERVERLESS_ROLES: ServerlessRoleName[] = [
  "serverless_t1_analyst",
  "serverless_t2_analyst",
  "serverless_soc_manager",
];

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    roles: ["full", "readonly"],
    mode: "stateful",
    cleanupStale: false,
    cleanup: true,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--mode") {
      const value = argv[++i];
      if (value === "stateful" || value === "serverless") opts.mode = value;
      else die(`Unknown --mode value: ${value} (expected stateful|serverless)`);
    } else if (arg === "--role") {
      const value = argv[++i];
      if (value === "both") opts.roles = ["full", "readonly"];
      else if (value === "all") opts.roles = [...ALL_ASSERTED_ROLES];
      else if (value === "quickstart")
        opts.roles = ["quickstart_full", "quickstart_readonly"];
      else if (value === "serverless") opts.roles = [...ALL_SERVERLESS_ROLES];
      else if (value === "serverless_all")
        opts.roles = [...ALL_ASSERTED_ROLES, ...ALL_SERVERLESS_ROLES];
      else if (value === "none") opts.roles = [];
      else if (
        value === "full" ||
        value === "readonly" ||
        value === "quickstart_full" ||
        value === "quickstart_readonly" ||
        value === "serverless_t1_analyst" ||
        value === "serverless_t2_analyst" ||
        value === "serverless_soc_manager"
      )
        opts.roles = [value];
      else
        die(
          `Unknown --role value: ${value} (expected full|readonly|quickstart_full|quickstart_readonly|both|quickstart|all|none|serverless|serverless_all|serverless_t1_analyst|serverless_t2_analyst|serverless_soc_manager)`
        );
    } else if (arg === "--cleanup-stale") {
      opts.cleanupStale = true;
    } else if (arg === "--no-cleanup") {
      opts.cleanup = false;
    } else if (arg === "--verbose" || arg === "-v") {
      opts.verbose = true;
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else {
      die(`Unknown argument: ${arg}`);
    }
  }
  return opts;
}

function printHelp() {
  console.log(`Usage: npm run test:permissions -- [options]

Options:
  --mode <stateful|serverless>  Deployment mode (default: stateful).
  --role <name|alias>           Role(s) to test (default: both).
                                Stateful names: full, readonly, quickstart_full, quickstart_readonly.
                                Stateful aliases: "both" = full,readonly. "quickstart" = quickstart_*.
                                  "all" = all four stateful roles.
                                Serverless names: serverless_t1_analyst, serverless_t2_analyst, serverless_soc_manager.
                                Serverless aliases: "serverless" = all 3 built-in roles.
                                  "serverless_all" = all stateful + all serverless.
                                "none" = no roles (cleanup-stale only).
  --cleanup-stale               Delete leftover ${TEST_RESOURCE_PREFIX}* roles/users/keys before running
  --no-cleanup                  Skip cleanup at end (prints API keys for reuse)
  --verbose                     Verbose output
  -h, --help                    Show this help
`);
}

function die(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

interface AdminBasics {
  elasticsearchUrl: string;
  kibanaUrl: string;
  basicAuth: { username: string; password: string };
}

function loadAdminBasics(mode: DeploymentMode): AdminBasics {
  const elasticsearchUrl = process.env.ELASTICSEARCH_URL;
  const kibanaUrl = process.env.KIBANA_URL;
  // Serverless local dev uses "elastic_serverless"; stateful uses "elastic".
  // Both can be overridden via ELASTIC_USERNAME env var.
  const defaultUsername = mode === "serverless" ? "elastic_serverless" : "elastic";
  const username = process.env.ELASTIC_USERNAME || defaultUsername;
  const password = process.env.ELASTIC_PASSWORD;
  if (!elasticsearchUrl || !kibanaUrl || !password) {
    die(
      "ELASTICSEARCH_URL, KIBANA_URL, and ELASTIC_PASSWORD must be set in .env or the environment. " +
        `ELASTIC_USERNAME defaults to '${defaultUsername}' in ${mode} mode.`
    );
  }
  return {
    elasticsearchUrl,
    kibanaUrl,
    basicAuth: { username, password },
  };
}

function adminServices(admin: AdminConfig): Services {
  const creds: ClusterCredentials = {
    name: ADMIN_CLUSTER_NAME,
    elasticsearchUrl: admin.elasticsearchUrl,
    kibanaUrl: admin.kibanaUrl,
    elasticsearchApiKey: admin.elasticsearchApiKey,
    sslVerify: true,
  };
  return buildServices(creds);
}

function scopedServices(admin: AdminConfig, scopedKey: string): Services {
  const creds: ClusterCredentials = {
    name: SCOPED_CLUSTER_NAME,
    elasticsearchUrl: admin.elasticsearchUrl,
    kibanaUrl: admin.kibanaUrl,
    elasticsearchApiKey: scopedKey,
    sslVerify: true,
  };
  return buildServices(creds);
}

function isPermissionDenied(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  // Direct ES/Kibana 403/401 throws. The client interceptor formats these
  // as e.g. `Elasticsearch [<cluster>] 403: ...` / `Kibana [<cluster>] 403: ...`.
  if (/Elasticsearch\s+(?:\[[^\]]+\]\s+)?403:|Kibana\s+(?:\[[^\]]+\]\s+)?(?:403|401):/i.test(msg))
    return true;
  // Bulk-API path: HTTP 200 with per-doc errors. The first error JSON
  // contains `"status":403` or `security_exception`.
  if (/security_exception/i.test(msg)) return true;
  if (/"status"\s*:\s*403/.test(msg)) return true;
  // Kibana bulk-endpoint path (e.g. /api/detection_engine/rules/_bulk_action):
  // top-level HTTP is 500, but the per-rule denial is reported as
  // `"status_code":403` inside `attributes.errors[]`. Without this any
  // op that goes through one of those endpoints would be classified
  // "other" instead of "403" by the runner.
  if (/"status_code"\s*:\s*403/.test(msg)) return true;
  return false;
}

function isNotFound(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /(?:Elasticsearch|Kibana)\s+(?:\[[^\]]+\]\s+)?404:|not_found/i.test(msg);
}

interface ObservedRun {
  check: OperationCheck;
  outcome: RunOutcome;
  detail: string;
}

/**
 * Runs every operation check against the supplied services bundle and
 * returns the *observed* outcome for each — without comparing to any
 * expectation. Used both for built-in discovery (where there's no
 * expectation) and as the raw layer underneath asserted runs.
 */
async function runOpsObserve(
  services: Services,
  role: AnyRoleName,
  fixtures: SeedFixtures
): Promise<ObservedRun[]> {
  const out: ObservedRun[] = [];
  for (const check of operationChecks) {
    if (check.skipUnless && !check.skipUnless(fixtures, role)) {
      out.push({
        check,
        outcome: "skipped",
        detail: "no fixture available for this check",
      });
      continue;
    }
    try {
      const value = await check.run({ services, fixtures, role });
      out.push({ check, outcome: "pass", detail: summarize(value) });
    } catch (err) {
      const msg = formatError(err);
      if (isPermissionDenied(err)) {
        out.push({ check, outcome: "403", detail: "denied (403/401)" });
      } else if (isNotFound(err)) {
        out.push({ check, outcome: "404", detail: msg });
      } else {
        out.push({ check, outcome: "other", detail: msg });
      }
    }
  }
  return out;
}

const DISCOVERY_INDEX = ".alerts-security.attack.discovery.alerts-default";

/**
 * Returns a discovery `_id` to use as fixture for `acknowledgeDiscoveries`.
 * Reuses an existing discovery if one is present; otherwise seeds a
 * minimal one via `_bulk` (silent on failure — the check skips when no
 * discoveryId is captured).
 */
async function ensureDiscoveryFixture(
  services: Services,
  opts: CliOptions
): Promise<string | undefined> {
  try {
    const existing = await services.esClient.request<{
      hits: { hits: Array<{ _id: string }> };
    }>({
      url: `/${DISCOVERY_INDEX}/_search`,
      method: "POST",
      data: { size: 1, _source: false, query: { match_all: {} } },
    });
    const hit = existing.data.hits?.hits?.[0];
    if (hit) {
      if (opts.verbose) console.log(`→ Reusing existing discovery ${hit._id}`);
      return hit._id;
    }
  } catch {
    /* index may not exist yet — fall through to seed */
  }

  if (opts.verbose) console.log("→ No discoveries found, seeding one…");
  const now = new Date().toISOString();
  const doc = {
    "@timestamp": now,
    "kibana.alert.uuid": crypto.randomUUID(),
    "kibana.alert.workflow_status": "open",
    "kibana.alert.rule.execution.uuid": crypto.randomUUID(),
    "kibana.alert.attack_discovery.title": "mcp-app-test seed discovery",
    "kibana.alert.attack_discovery.summary_markdown": "Permissions test seed (safe to delete)",
    "kibana.alert.attack_discovery.details_markdown": "Permissions test seed (safe to delete)",
    "kibana.alert.attack_discovery.alert_ids": [],
    "kibana.alert.attack_discovery.alerts_context_count": 0,
    "kibana.alert.risk_score": 0,
    "kibana.space_ids": ["default"],
    "kibana.alert.rule.tags": [TEST_TAG],
  };
  const body =
    JSON.stringify({ create: { _index: DISCOVERY_INDEX } }) + "\n" +
    JSON.stringify(doc) + "\n";
  try {
    const response = await services.esClient.request<{
      items: Array<{ create: { _id: string; status: number; error?: unknown } }>;
      errors: boolean;
    }>({
      url: "/_bulk",
      method: "POST",
      data: body,
      params: { refresh: "true" },
      headers: { "Content-Type": "application/x-ndjson" },
    });
    const result = response.data;
    if (result.errors) {
      const err = result.items[0]?.create?.error;
      console.warn(
        `  warning: failed to seed discovery, acknowledgeDiscoveries will be skipped: ${JSON.stringify(err)}`
      );
      return undefined;
    }
    return result.items[0].create._id;
  } catch (err) {
    console.warn(
      `  warning: failed to seed discovery, acknowledgeDiscoveries will be skipped: ${err instanceof Error ? err.message : String(err)}`
    );
    return undefined;
  }
}

/**
 * Creates a transient detection-type exception list under a unique
 * `list_id` so the `listExceptions` / `addException` checks have a
 * fixture they can read against and write to. Returns the `list_id`
 * (the value `_find` filters on — not the Saved Object id).
 *
 * Why we don't use `endpoint_list`: it's only present after the Endpoint
 * Security integration is enabled. On a vanilla cluster `_find?list_id=
 * endpoint_list` returns 404, which the runner classifies as "no fixture"
 * and the privilege check skips. Seeding our own list keeps the check
 * deterministic across environments. Mirrors `ensureDiscoveryFixture`.
 */
async function ensureExceptionListFixture(
  services: Services,
  opts: CliOptions
): Promise<string | undefined> {
  const listId = `mcp-app-test-list-${crypto.randomBytes(4).toString("hex")}`;
  if (opts.verbose) console.log(`→ Seeding exception list ${listId}…`);
  try {
    await services.kibanaClient.request({
      url: "/api/exception_lists",
      method: "POST",
      headers: { "elastic-api-version": "2023-10-31" },
      data: {
        list_id: listId,
        name: listId,
        description: "Permissions test exception list (safe to delete)",
        type: "detection",
        namespace_type: "single",
      },
    });
    return listId;
  } catch (err) {
    console.warn(
      `  warning: failed to seed exception list, listExceptions/addException will be skipped: ${err instanceof Error ? err.message : String(err)}`
    );
    return undefined;
  }
}

async function deleteExceptionListFixture(
  services: Services,
  listId: string
): Promise<void> {
  try {
    await services.kibanaClient.request({
      url: "/api/exception_lists",
      method: "DELETE",
      headers: { "elastic-api-version": "2023-10-31" },
      params: { list_id: listId, namespace_type: "single" },
    });
  } catch (err) {
    console.warn(
      `  warning: failed to delete exception list ${listId}: ${formatError(err)}`
    );
  }
}

async function preflight(
  services: Services,
  opts: CliOptions
): Promise<SeedFixtures> {
  if (opts.verbose) console.log("→ Verifying admin connectivity…");
  // A trivial call confirms ES + key are reachable.
  let existing = await services.sampleDataService.checkExistingData();

  if (existing.totalAlerts === 0) {
    console.log("→ No security alerts found, seeding sample data (count=50)…");
    await services.sampleDataService.generateSampleData({ count: 50 });
    existing = await services.sampleDataService.checkExistingData();
    if (existing.totalAlerts === 0) {
      die(
        "Seeding completed but no security alerts were created. Aborting — Layer B checks need at least one alert."
      );
    }
  } else if (opts.verbose) {
    console.log(
      `→ Cluster has ${existing.totalAlerts} alert(s); skipping sample-data seed.`
    );
  }

  // Capture one alert.
  const alerts = await services.alertsService.getAlerts({
    days: 365,
    limit: 1,
    status: "open",
  });
  let alertHit = alerts.alerts[0];
  if (!alertHit) {
    // Fall back to acknowledged alerts if all alerts have been triaged.
    const triaged = await services.alertsService.getAlerts({
      days: 365,
      limit: 1,
      status: "acknowledged",
    });
    alertHit = triaged.alerts[0];
  }
  if (!alertHit) {
    die("No alerts available even after seeding. Cannot run alert-related Layer B checks.");
  }

  const alertSrc = alertHit._source;
  const alertRuleId = String(
    (alertSrc["kibana.alert.rule.uuid"] as string) ||
      (alertSrc["kibana.alert.rule.rule_id"] as string) ||
      ""
  );
  const alertRuleName = String((alertSrc["kibana.alert.rule.name"] as string) || "");

  // Capture or create one case. Operations that need a version refetch it
  // themselves at call time, so the version isn't stored in fixtures.
  const caseList = await services.casesService.listCases({ perPage: 1 });
  let caseId: string;
  if (caseList.cases[0]) {
    caseId = caseList.cases[0].id;
  } else {
    if (opts.verbose) console.log("→ No cases found, creating a seed case…");
    const newCase = await services.casesService.createCase({
      title: `mcp-app-test seed case ${new Date().toISOString()}`,
      description: "Seed case created by test-permissions runner",
      tags: ["mcp-app-test"],
    });
    caseId = newCase.id;
  }

  // Capture an existing rule (best-effort; missing rule just causes patchRule to skip).
  let ruleId: string | undefined;
  try {
    const rules = await services.rulesService.findRules({ perPage: 1 });
    ruleId = rules.data[0]?.id;
  } catch {
    /* rules feature might not be available */
  }

  const discoveryId = await ensureDiscoveryFixture(services, opts);
  const exceptionListId = await ensureExceptionListFixture(services, opts);

  return {
    alertId: alertHit._id,
    alertIndex: alertHit._index,
    alertRuleId,
    alertRuleName,
    caseId,
    ruleId,
    discoveryId,
    exceptionListId,
    suffix: crypto.randomBytes(4).toString("hex"),
  };
}

async function cleanupStaleResources(
  services: Services,
  opts: CliOptions
): Promise<void> {
  const keys = await listApiKeysByPrefix(services.esClient, TEST_RESOURCE_PREFIX);
  for (const k of keys) {
    if (opts.verbose) console.log(`→ Invalidating stale API key: ${k.name} (${k.id})`);
    try {
      await deleteApiKey(services.esClient, k.id);
    } catch (err) {
      console.warn(`  warning: failed to invalidate ${k.id}: ${formatError(err)}`);
    }
  }
  const roles = await listRolesByPrefix(services.esClient, TEST_RESOURCE_PREFIX);
  for (const r of roles) {
    if (opts.verbose) console.log(`→ Deleting stale role: ${r}`);
    try {
      await deleteRole(services.esClient, r);
    } catch (err) {
      console.warn(`  warning: failed to delete role ${r}: ${formatError(err)}`);
    }
  }
  const users = await listUsersByPrefix(services.esClient, TEST_RESOURCE_PREFIX);
  for (const u of users) {
    if (opts.verbose) console.log(`→ Deleting stale user: ${u}`);
    try {
      await deleteUser(services.esClient, u);
    } catch (err) {
      console.warn(`  warning: failed to delete user ${u}: ${formatError(err)}`);
    }
  }
}

async function provisionQuickstart(
  services: Services,
  admin: AdminConfig,
  role: QuickstartRoleName,
  suffix: string
): Promise<QuickstartArtifacts | UnavailableQuickstart> {
  const builtin = QUICKSTART_BUILTINS[role];
  if (!(await roleExists(services.esClient, builtin))) {
    return { role, reason: `built-in '${builtin}' not present in cluster` };
  }
  const descriptor = QUICKSTART_COMPANION_DESCRIPTORS[role];
  const companionRoleName = `${TEST_RESOURCE_PREFIX}${role}-companion-${suffix}`;
  const username = `${TEST_RESOURCE_PREFIX}${role}-${suffix}`;
  const password = crypto.randomBytes(18).toString("base64");
  await createRole(services.esClient, companionRoleName, descriptor);
  let apiKey: CreatedApiKey;
  try {
    await createUser(services.esClient, username, password, [builtin, companionRoleName]);
    apiKey = await grantApiKeyForUser(
      {
        elasticsearchUrl: admin.elasticsearchUrl,
        username: admin.basicAuth.username,
        password: admin.basicAuth.password,
      },
      username,
      password,
      username
    );
  } catch (err) {
    // Best-effort cleanup so a failed provisioning leaves no orphans.
    try {
      await deleteUser(services.esClient, username);
    } catch {
      /* swallow */
    }
    try {
      await deleteRole(services.esClient, companionRoleName);
    } catch {
      /* swallow */
    }
    throw err;
  }
  return { role, companionRoleName, username, apiKey };
}

async function provisionRole(
  services: Services,
  admin: AdminConfig,
  role: "full" | "readonly",
  suffix: string
): Promise<RoleArtifacts> {
  const descriptor = ROLE_DESCRIPTORS[role];
  const roleName = `${TEST_RESOURCE_PREFIX}${role}-${suffix}`;
  await createRole(services.esClient, roleName, descriptor);
  const apiKey = await createApiKey(
    {
      elasticsearchUrl: admin.elasticsearchUrl,
      username: admin.basicAuth.username,
      password: admin.basicAuth.password,
    },
    roleName,
    roleName,
    descriptor
  );
  return { role, roleName, apiKey };
}

interface ServerlessBuiltinArtifacts {
  role: ServerlessRoleName;
  apiKey: CreatedApiKey;
}

interface ServerlessBuiltinUnavailable {
  role: ServerlessRoleName;
  reason: string;
}

/**
 * Provisions a scoped API key for a serverless built-in role user. The user
 * already exists as a file-realm user in the local serverless cluster — no
 * role or user creation needed. The key is invalidated on cleanup.
 */
async function provisionServerlessBuiltin(
  admin: AdminConfig,
  role: ServerlessRoleName,
  suffix: string
): Promise<ServerlessBuiltinArtifacts | ServerlessBuiltinUnavailable> {
  const { roleName, password } = SERVERLESS_BUILTINS[role];
  const keyName = `${TEST_RESOURCE_PREFIX}serverless-${roleName}-${suffix}`;
  try {
    const apiKey = await grantApiKeyForUser(
      {
        elasticsearchUrl: admin.elasticsearchUrl,
        username: admin.basicAuth.username,
        password: admin.basicAuth.password,
      },
      roleName,
      password,
      keyName
    );
    return { role, apiKey };
  } catch (err) {
    return { role, reason: formatError(err) };
  }
}

interface LayerAResult {
  role: "full" | "readonly";
  outcome: "pass" | "fail";
  detail: string;
}

async function runLayerA(
  role: "full" | "readonly",
  services: Services
): Promise<LayerAResult> {
  const descriptor = ROLE_DESCRIPTORS[role];

  const probe = {
    cluster: descriptor.cluster,
    index: descriptor.indices.map((i) => ({
      names: i.names,
      privileges: i.privileges,
    })),
    application: descriptor.applications.map(
      (a: RoleDescriptorApplication) => ({
        application: a.application,
        privileges: a.privileges,
        resources: a.resources,
      })
    ),
  };

  try {
    const result = await hasPrivileges(services.esClient, probe);
    if (result.has_all_requested) {
      return {
        role,
        outcome: "pass",
        detail: "all requested privileges granted",
      };
    }
    const missing = collectMissing(result);
    return {
      role,
      outcome: "fail",
      detail: `missing privileges: ${missing.join(", ") || "(unknown)"}`,
    };
  } catch (err) {
    return {
      role,
      outcome: "fail",
      detail: `_has_privileges call failed: ${formatError(err)}`,
    };
  }
}

interface RoleDescriptorApplication {
  application: string;
  privileges: string[];
  resources: string[];
}

function collectMissing(result: {
  cluster: Record<string, boolean>;
  index: Record<string, Record<string, boolean>>;
  application: Record<string, Record<string, Record<string, boolean>>>;
}): string[] {
  const missing: string[] = [];
  for (const [priv, granted] of Object.entries(result.cluster || {})) {
    if (!granted) missing.push(`cluster:${priv}`);
  }
  for (const [name, privs] of Object.entries(result.index || {})) {
    for (const [priv, granted] of Object.entries(privs || {})) {
      if (!granted) missing.push(`index:${name}:${priv}`);
    }
  }
  for (const [app, resources] of Object.entries(result.application || {})) {
    for (const [resource, privs] of Object.entries(resources || {})) {
      for (const [priv, granted] of Object.entries(privs || {})) {
        if (!granted) missing.push(`${app}:${resource}:${priv}`);
      }
    }
  }
  return missing;
}

async function runLayerB(
  role: AssertedRoleName,
  services: Services,
  fixtures: SeedFixtures
): Promise<{ checkResults: CheckResult[]; observed: ObservedRun[] }> {
  const observed = await runOpsObserve(services, role, fixtures);
  const checkResults: CheckResult[] = observed.map((o) =>
    deriveCheckResult(role, o)
  );
  return { checkResults, observed };
}

function deriveCheckResult(
  role: AssertedRoleName,
  o: ObservedRun
): CheckResult {
  if (o.outcome === "skipped") {
    return { check: o.check, role, outcome: "skipped", detail: o.detail };
  }
  const expectation = o.check.expect[ASSERTED_EXPECTATION_PROFILE[role]];
  if (expectation === "ok") {
    if (o.outcome === "pass") {
      return { check: o.check, role, outcome: "pass", detail: o.detail };
    }
    if (o.outcome === "404") {
      return {
        check: o.check,
        role,
        outcome: "skipped",
        detail: `no fixture in cluster: ${o.detail}`,
      };
    }
    if (o.outcome === "403") {
      return {
        check: o.check,
        role,
        outcome: "fail",
        detail: `expected ok but got 403/401`,
      };
    }
    return { check: o.check, role, outcome: "fail", detail: o.detail };
  }
  // expectation === "403"
  if (o.outcome === "403") {
    return { check: o.check, role, outcome: "pass", detail: o.detail };
  }
  if (o.outcome === "pass") {
    return {
      check: o.check,
      role,
      outcome: "fail",
      detail: `expected 403 but call succeeded`,
    };
  }
  return {
    check: o.check,
    role,
    outcome: "fail",
    detail: `expected 403 but got non-permission error: ${o.detail}`,
  };
}

interface LeftoverCounts {
  cases: number;
  rules: number;
}

/**
 * Counts cases and detection rules currently tagged `mcp-app-test`. Run
 * under the admin key. Used at end of run to surface what tag-scoped
 * cleanup the user may want to do via Kibana.
 */
async function countLeftoverTaggedResources(
  services: Services
): Promise<LeftoverCounts> {
  let cases = 0;
  let rules = 0;
  try {
    const result = await services.casesService.listCases({
      tags: [TEST_TAG],
      perPage: 1,
    });
    cases = result.total;
  } catch {
    /* cases API unavailable — leave at 0 */
  }
  try {
    const result = await services.rulesService.findRules({
      filter: `alert.attributes.tags:"${TEST_TAG}"`,
      perPage: 1,
    });
    rules = result.total;
  } catch {
    /* rules API unavailable — leave at 0 */
  }
  return { cases, rules };
}

function summarize(value: unknown): string {
  if (value === undefined || value === null) return "ok";
  if (typeof value === "string") return value.slice(0, 80);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `array(${value.length})`;
  try {
    const json = JSON.stringify(value);
    return json.length > 80 ? `${json.slice(0, 77)}…` : json;
  } catch {
    return "ok";
  }
}

function formatError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function symbolFor(outcome: "pass" | "fail" | "skipped"): string {
  if (outcome === "pass") return SYM_OK;
  if (outcome === "fail") return SYM_FAIL;
  return SYM_SKIP;
}

function printRoleReport(
  role: AssertedRoleName,
  layerA: LayerAResult | null,
  layerB: CheckResult[]
) {
  console.log(`\n── ${role.toUpperCase()} ──`);

  if (layerA) {
    console.log("  Layer A (_has_privileges):");
    console.log(
      `    ${symbolFor(layerA.outcome)} all role privileges granted — ${layerA.detail}`
    );
  } else {
    console.log(
      "  Layer A: skipped (built-in privileges aren't enumerable from the role descriptor)"
    );
  }

  console.log("  Layer B (operations):");
  for (const group of GROUP_ORDER) {
    const inGroup = layerB.filter((r) => r.check.group === group);
    if (inGroup.length === 0) continue;
    console.log(`    [${group}]`);
    for (const r of inGroup) {
      const expected = r.check.expect[ASSERTED_EXPECTATION_PROFILE[role]];
      console.log(
        `      ${symbolFor(r.outcome)} ${r.check.name} (expect ${expected}) — ${r.detail}`
      );
    }
  }
}

function outcomeSymbol(outcome: RunOutcome): string {
  if (outcome === "pass") return SYM_OK;
  if (outcome === "403") return SYM_FAIL;
  return SYM_SKIP;
}

function printObservedReport(role: ServerlessRoleName, observed: ObservedRun[]) {
  console.log(`\n── ${role.toUpperCase()} (observe-only) ──`);
  console.log(
    "  Layer A: skipped (built-in role — privileges not enumerable from a role descriptor)"
  );
  console.log("  Layer B (operations, observed — no pass/fail assertions):");
  for (const group of GROUP_ORDER) {
    const inGroup = observed.filter((r) => r.check.group === group);
    if (inGroup.length === 0) continue;
    console.log(`    [${group}]`);
    for (const r of inGroup) {
      console.log(
        `      ${outcomeSymbol(r.outcome)} ${r.check.name} — ${r.outcome}: ${r.detail}`
      );
    }
  }
}

async function cleanupRoleArtifacts(
  adminSvc: Services,
  artifacts: RoleArtifacts[],
  quickstartArtifacts: QuickstartArtifacts[],
  serverlessArtifacts: ServerlessBuiltinArtifacts[],
  exceptionListId: string | undefined,
  opts: CliOptions
) {
  if (!opts.cleanup) {
    console.log("\n→ Skipping cleanup (--no-cleanup). Provisioned resources:");
    for (const a of artifacts) {
      console.log(`    role:    ${a.roleName}`);
      console.log(`    api key: ${a.apiKey.name} (id=${a.apiKey.id})`);
      console.log(`    encoded: ${a.apiKey.encoded}`);
    }
    for (const q of quickstartArtifacts) {
      console.log(`    user:    ${q.username} (quickstart: ${q.role})`);
      console.log(`    role:    ${q.companionRoleName}`);
      console.log(`    api key: ${q.apiKey.name} (id=${q.apiKey.id})`);
      console.log(`    encoded: ${q.apiKey.encoded}`);
    }
    for (const s of serverlessArtifacts) {
      console.log(`    serverless role: ${s.role}`);
      console.log(`    api key: ${s.apiKey.name} (id=${s.apiKey.id})`);
      console.log(`    encoded: ${s.apiKey.encoded}`);
    }
    if (exceptionListId) {
      console.log(`    exception list: ${exceptionListId} (namespace_type=single)`);
    }
    return;
  }
  if (exceptionListId) {
    await deleteExceptionListFixture(adminSvc, exceptionListId);
  }
  for (const a of artifacts) {
    try {
      await deleteApiKey(adminSvc.esClient, a.apiKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate API key ${a.apiKey.id}: ${formatError(err)}`
      );
    }
    try {
      await deleteRole(adminSvc.esClient, a.roleName);
    } catch (err) {
      console.warn(
        `  warning: failed to delete role ${a.roleName}: ${formatError(err)}`
      );
    }
  }
  for (const q of quickstartArtifacts) {
    try {
      await deleteApiKey(adminSvc.esClient, q.apiKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate API key ${q.apiKey.id}: ${formatError(err)}`
      );
    }
    try {
      await deleteUser(adminSvc.esClient, q.username);
    } catch (err) {
      console.warn(
        `  warning: failed to delete user ${q.username}: ${formatError(err)}`
      );
    }
    try {
      await deleteRole(adminSvc.esClient, q.companionRoleName);
    } catch (err) {
      console.warn(
        `  warning: failed to delete role ${q.companionRoleName}: ${formatError(err)}`
      );
    }
  }
  for (const s of serverlessArtifacts) {
    try {
      await deleteApiKey(adminSvc.esClient, s.apiKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate API key ${s.apiKey.id}: ${formatError(err)}`
      );
    }
  }
}

function isServerlessRole(role: RoleName): role is ServerlessRoleName {
  return role in SERVERLESS_BUILTINS;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const basics = loadAdminBasics(opts.mode);

  // Bootstrap an admin API key via Basic auth. Two reasons:
  //  1. The standard ES + Kibana client factories only support
  //     `Authorization: ApiKey ...` and we need an admin-privilege key for
  //     seed-fixture queries (fetchAlerts, listCases, createCase, etc.).
  //  2. The user may not have a usable API key in .env (we don't want to
  //     require them to mint one manually). Basic auth is the
  //     local-dev-friendly path.
  const bootstrapKeyName = `mcp-runner-bootstrap-${crypto.randomBytes(4).toString("hex")}`;
  if (opts.verbose) console.log(`→ Bootstrapping admin API key "${bootstrapKeyName}"…`);
  const bootstrapKey = await bootstrapAdminApiKey(
    {
      elasticsearchUrl: basics.elasticsearchUrl,
      username: basics.basicAuth.username,
      password: basics.basicAuth.password,
    },
    bootstrapKeyName
  );
  const admin: AdminConfig = {
    elasticsearchUrl: basics.elasticsearchUrl,
    elasticsearchApiKey: bootstrapKey.encoded,
    basicAuth: basics.basicAuth,
    kibanaUrl: basics.kibanaUrl,
  };

  // The admin services bundle is the long-lived "control plane" — used
  // for provisioning, cleanup, and fixture seeding. A short-lived "data
  // plane" bundle is built per role swap inside the run loop below.
  const adminSvc = adminServices(admin);

  const provisioned: RoleArtifacts[] = [];
  const provisionedQuickstarts: QuickstartArtifacts[] = [];
  const provisionedServerless: ServerlessBuiltinArtifacts[] = [];
  let seededExceptionListId: string | undefined;
  let interrupted = false;

  const cleanupBootstrap = async () => {
    try {
      await deleteApiKey(adminSvc.esClient, bootstrapKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate bootstrap admin key ${bootstrapKey.id}: ${formatError(err)}`
      );
    }
  };

  const onSignal = () => {
    interrupted = true;
    console.log("\n→ Caught SIGINT, cleaning up before exit…");
    cleanupRoleArtifacts(
      adminSvc,
      provisioned,
      provisionedQuickstarts,
      provisionedServerless,
      seededExceptionListId,
      opts
    )
      .then(() => cleanupBootstrap())
      .catch((err) => console.error(`Cleanup error: ${formatError(err)}`))
      .finally(() => process.exit(130));
  };
  process.on("SIGINT", onSignal);

  let exitCode = 0;
  try {
    if (opts.cleanupStale) {
      console.log(`→ --cleanup-stale: removing leftover ${TEST_RESOURCE_PREFIX}* resources…`);
      await cleanupStaleResources(adminSvc, opts);
    }

    console.log("→ Pre-flight: checking connectivity and seed data…");
    const fixtures = await preflight(adminSvc, opts);
    seededExceptionListId = fixtures.exceptionListId;
    if (opts.verbose) {
      console.log(`  alertId:          ${fixtures.alertId}`);
      console.log(`  alertIndex:       ${fixtures.alertIndex}`);
      console.log(`  alertRuleId:      ${fixtures.alertRuleId}`);
      console.log(`  caseId:           ${fixtures.caseId}`);
      console.log(`  ruleId:           ${fixtures.ruleId ?? "(none — patchRule will skip)"}`);
      console.log(`  exceptionListId:  ${fixtures.exceptionListId ?? "(none — listExceptions/addException will skip)"}`);
      console.log(`  suffix:           ${fixtures.suffix}`);
    }

    interface AssertedRun {
      role: AssertedRoleName;
      layerA: LayerAResult | null;
      layerB: CheckResult[];
    }
    interface ObservedRoleRun {
      role: ServerlessRoleName;
      observed: ObservedRun[];
    }
    const assertedRuns: AssertedRun[] = [];
    const observedRoleRuns: ObservedRoleRun[] = [];
    const unavailableQuickstarts: UnavailableQuickstart[] = [];
    const unavailableServerless: ServerlessBuiltinUnavailable[] = [];

    for (const role of opts.roles) {
      console.log(`\n→ Provisioning role "${role}"…`);

      if (isServerlessRole(role)) {
        const result = await provisionServerlessBuiltin(admin, role, fixtures.suffix);
        if ("reason" in result) {
          console.warn(`  ! ${role} unavailable: ${result.reason}`);
          unavailableServerless.push(result);
          continue;
        }
        provisionedServerless.push(result);
        const scopedSvc = scopedServices(admin, result.apiKey.encoded);
        const observed = await runOpsObserve(scopedSvc, role, fixtures);
        observedRoleRuns.push({ role, observed });
        continue;
      }

      let apiKey: CreatedApiKey;
      let layerA: LayerAResult | null = null;
      if (role === "full" || role === "readonly") {
        const artifacts = await provisionRole(adminSvc, admin, role, fixtures.suffix);
        provisioned.push(artifacts);
        apiKey = artifacts.apiKey;
        // Layer A runs as the scoped role (the privilege check answers
        // "does this caller have these privileges?", which only makes
        // sense for the scoped key, not the admin).
        const layerASvc = scopedServices(admin, apiKey.encoded);
        layerA = await runLayerA(role, layerASvc);
      } else {
        const result = await provisionQuickstart(adminSvc, admin, role, fixtures.suffix);
        if ("reason" in result) {
          console.warn(`  ! ${role} unavailable: ${result.reason}`);
          unavailableQuickstarts.push(result);
          continue;
        }
        provisionedQuickstarts.push(result);
        apiKey = result.apiKey;
      }
      const scopedSvc = scopedServices(admin, apiKey.encoded);
      const { checkResults } = await runLayerB(role, scopedSvc, fixtures);
      assertedRuns.push({ role, layerA, layerB: checkResults });
    }

    let passed = 0;
    let failed = 0;
    let skipped = 0;
    for (const { role, layerA, layerB } of assertedRuns) {
      printRoleReport(role, layerA, layerB);
      if (layerA) {
        if (layerA.outcome === "pass") passed++;
        else failed++;
      }
      for (const r of layerB) {
        if (r.outcome === "pass") passed++;
        else if (r.outcome === "fail") failed++;
        else skipped++;
      }
    }

    for (const { role, observed } of observedRoleRuns) {
      printObservedReport(role, observed);
    }

    if (unavailableServerless.length > 0) {
      console.log("\nUnavailable serverless built-in roles (skipped):");
      for (const u of unavailableServerless) {
        console.log(`  ! ${u.role}: ${u.reason}`);
      }
    }

    if (assertedRuns.length > 0) {
      console.log(
        `\nSummary (asserted roles): ${passed} passed, ${failed} failed, ${skipped} skipped`
      );
    }
    if (observedRoleRuns.length > 0) {
      console.log(
        `Observed (serverless built-ins): ${observedRoleRuns.length} role(s) run — see reports above for details.`
      );
    }

    // Surface leftover test resources so the user can clean them up. We
    // query through the admin services bundle to make sure we see
    // everything regardless of which scoped role most recently ran.
    const leftover = await countLeftoverTaggedResources(adminSvc);
    if (leftover.cases > 0 || leftover.rules > 0) {
      const parts: string[] = [];
      if (leftover.cases > 0) parts.push(`${leftover.cases} case(s)`);
      if (leftover.rules > 0) parts.push(`${leftover.rules} rule(s)`);
      console.log(
        `Note: ${parts.join(", ")} tagged "${TEST_TAG}" remain in the cluster — clean up via Kibana > Stack Management or with a tag-scoped delete.`
      );
    }

    exitCode = failed === 0 ? 0 : 1;
  } catch (err) {
    console.error(`\nFatal error: ${formatError(err)}`);
    exitCode = 1;
  } finally {
    if (!interrupted) {
      try {
        await cleanupRoleArtifacts(
          adminSvc,
          provisioned,
          provisionedQuickstarts,
          provisionedServerless,
          seededExceptionListId,
          opts
        );
      } catch (err) {
        console.error(`Cleanup error: ${formatError(err)}`);
        if (exitCode === 0) exitCode = 1;
      }
      // The bootstrap admin API key is always invalidated, even when the
      // user asked --no-cleanup (which only preserves the per-role
      // scoped keys for debugging). Leaving the bootstrap key around
      // would be a real footgun: it carries admin privileges.
      await cleanupBootstrap();
    }
  }
  process.exit(exitCode);
}

main().catch((err) => {
  console.error(formatError(err));
  process.exit(1);
});

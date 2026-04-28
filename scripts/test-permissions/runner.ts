/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import "dotenv/config";
import crypto from "node:crypto";

import { setConfig } from "../../src/elastic/client.js";
import {
  checkExistingData,
  generateSampleData,
} from "../../src/elastic/sample-data.js";
import { fetchAlerts } from "../../src/elastic/alerts.js";
import {
  listCases,
  createCase,
} from "../../src/elastic/cases.js";
import { findRules } from "../../src/elastic/rules.js";

const TEST_TAG = "mcp-app-test";
import {
  ASSERTED_EXPECTATION_PROFILE,
  QUICKSTART_BUILTINS,
  QUICKSTART_COMPANION_DESCRIPTORS,
  ROLE_DESCRIPTORS,
  operationChecks,
  type AnyRoleName,
  type AssertedRoleName,
  type CheckResult,
  type OperationCheck,
  type OperationGroup,
  type RoleName,
  type RunOutcome,
  type SeedFixtures,
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

const TEST_RESOURCE_PREFIX = "mcp-app-test-";

interface CliOptions {
  roles: RoleName[];
  cleanupStale: boolean;
  cleanup: boolean;
  verbose: boolean;
}

interface AdminConfig {
  elasticsearchUrl: string;
  /**
   * Bootstrapped admin API key (encoded). Created on startup via Basic
   * auth so we can authenticate esRequest/kibanaRequest calls — those
   * always send `Authorization: ApiKey ...`.
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

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    roles: ["full", "readonly"],
    cleanupStale: false,
    cleanup: true,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--role") {
      const value = argv[++i];
      if (value === "both") opts.roles = ["full", "readonly"];
      else if (value === "all") opts.roles = [...ALL_ASSERTED_ROLES];
      else if (value === "quickstart")
        opts.roles = ["quickstart_full", "quickstart_readonly"];
      else if (value === "none") opts.roles = [];
      else if (
        value === "full" ||
        value === "readonly" ||
        value === "quickstart_full" ||
        value === "quickstart_readonly"
      )
        opts.roles = [value];
      else
        die(
          `Unknown --role value: ${value} (expected full|readonly|quickstart_full|quickstart_readonly|both|quickstart|all|none)`
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
  --role <name|both|quickstart|all|none>
                                Role(s) to test (default: both).
                                Names: full, readonly, quickstart_full, quickstart_readonly.
                                "both" = full,readonly. "quickstart" = quickstart_full,quickstart_readonly.
                                "all" = all four. "none" = no roles (cleanup-stale only).
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

function loadAdminBasics(): AdminBasics {
  const elasticsearchUrl = process.env.ELASTICSEARCH_URL;
  const kibanaUrl = process.env.KIBANA_URL;
  // Default to "elastic" — by far the most common admin user for local
  // dev clusters. Override via env if needed.
  const username = process.env.ELASTIC_USERNAME || "elastic";
  const password = process.env.ELASTIC_PASSWORD;
  if (!elasticsearchUrl || !kibanaUrl || !password) {
    die(
      "ELASTICSEARCH_URL, KIBANA_URL, and ELASTIC_PASSWORD must be set in .env or the environment. " +
        "ELASTIC_USERNAME defaults to 'elastic'."
    );
  }
  return {
    elasticsearchUrl,
    kibanaUrl,
    basicAuth: { username, password },
  };
}

function useAdminConfig(admin: AdminConfig) {
  setConfig({
    elasticsearchUrl: admin.elasticsearchUrl,
    elasticsearchApiKey: admin.elasticsearchApiKey,
    kibanaUrl: admin.kibanaUrl,
  });
}

function useScopedConfig(admin: AdminConfig, scopedKey: string) {
  setConfig({
    elasticsearchUrl: admin.elasticsearchUrl,
    elasticsearchApiKey: scopedKey,
    kibanaUrl: admin.kibanaUrl,
  });
}

function isPermissionDenied(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  // Direct ES/Kibana 403/401 throws.
  if (/Elasticsearch 403:|Kibana 403:|Kibana 401:/i.test(msg)) return true;
  // Bulk-API path: HTTP 200 with per-doc errors. The first error JSON
  // contains `"status":403` or `security_exception`.
  if (/security_exception/i.test(msg)) return true;
  if (/"status"\s*:\s*403/.test(msg)) return true;
  return false;
}

function isNotFound(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /Elasticsearch 404:|Kibana 404:|not_found/i.test(msg);
}

interface ObservedRun {
  check: OperationCheck;
  outcome: RunOutcome;
  detail: string;
}

/**
 * Runs every operation check against the currently active scoped key and
 * returns the *observed* outcome for each — without comparing to any
 * expectation. Used both for built-in discovery (where there's no
 * expectation) and as the raw layer underneath asserted runs.
 */
async function runOpsObserve(
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
      const value = await check.run(fixtures, role);
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

async function preflight(admin: AdminConfig, opts: CliOptions): Promise<SeedFixtures> {
  useAdminConfig(admin);

  if (opts.verbose) console.log("→ Verifying admin connectivity…");
  // A trivial call confirms ES + key are reachable.
  let existing = await checkExistingData();

  if (existing.totalAlerts === 0) {
    console.log("→ No security alerts found, seeding sample data (count=50)…");
    await generateSampleData({ count: 50 });
    existing = await checkExistingData();
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
  const alerts = await fetchAlerts({ days: 365, limit: 1, status: "open" });
  let alertHit = alerts.alerts[0];
  if (!alertHit) {
    // Fall back to acknowledged alerts if all alerts have been triaged.
    const triaged = await fetchAlerts({ days: 365, limit: 1, status: "acknowledged" });
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
  const caseList = await listCases({ perPage: 1 });
  let caseId: string;
  if (caseList.cases[0]) {
    caseId = caseList.cases[0].id;
  } else {
    if (opts.verbose) console.log("→ No cases found, creating a seed case…");
    const newCase = await createCase({
      title: `mcp-app-test seed case ${new Date().toISOString()}`,
      description: "Seed case created by test-permissions runner",
      tags: ["mcp-app-test"],
    });
    caseId = newCase.id;
  }

  // Capture an existing rule (best-effort; missing rule just causes patchRule to skip).
  let ruleId: string | undefined;
  try {
    const rules = await findRules({ perPage: 1 });
    ruleId = rules.data[0]?.id;
  } catch {
    /* rules feature might not be available */
  }

  return {
    alertId: alertHit._id,
    alertIndex: alertHit._index,
    alertRuleId,
    alertRuleName,
    caseId,
    ruleId,
    suffix: crypto.randomBytes(4).toString("hex"),
  };
}

async function cleanupStaleResources(opts: CliOptions): Promise<void> {
  const keys = await listApiKeysByPrefix(TEST_RESOURCE_PREFIX);
  for (const k of keys) {
    if (opts.verbose) console.log(`→ Invalidating stale API key: ${k.name} (${k.id})`);
    try {
      await deleteApiKey(k.id);
    } catch (err) {
      console.warn(`  warning: failed to invalidate ${k.id}: ${formatError(err)}`);
    }
  }
  const roles = await listRolesByPrefix(TEST_RESOURCE_PREFIX);
  for (const r of roles) {
    if (opts.verbose) console.log(`→ Deleting stale role: ${r}`);
    try {
      await deleteRole(r);
    } catch (err) {
      console.warn(`  warning: failed to delete role ${r}: ${formatError(err)}`);
    }
  }
  const users = await listUsersByPrefix(TEST_RESOURCE_PREFIX);
  for (const u of users) {
    if (opts.verbose) console.log(`→ Deleting stale user: ${u}`);
    try {
      await deleteUser(u);
    } catch (err) {
      console.warn(`  warning: failed to delete user ${u}: ${formatError(err)}`);
    }
  }
}

async function provisionQuickstart(
  admin: AdminConfig,
  role: QuickstartRoleName,
  suffix: string
): Promise<QuickstartArtifacts | UnavailableQuickstart> {
  const builtin = QUICKSTART_BUILTINS[role];
  if (!(await roleExists(builtin))) {
    return { role, reason: `built-in '${builtin}' not present in cluster` };
  }
  const descriptor = QUICKSTART_COMPANION_DESCRIPTORS[role];
  const companionRoleName = `${TEST_RESOURCE_PREFIX}${role}-companion-${suffix}`;
  const username = `${TEST_RESOURCE_PREFIX}${role}-${suffix}`;
  const password = crypto.randomBytes(18).toString("base64");
  await createRole(companionRoleName, descriptor);
  let apiKey: CreatedApiKey;
  try {
    await createUser(username, password, [builtin, companionRoleName]);
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
      await deleteUser(username);
    } catch {
      /* swallow */
    }
    try {
      await deleteRole(companionRoleName);
    } catch {
      /* swallow */
    }
    throw err;
  }
  return { role, companionRoleName, username, apiKey };
}

async function provisionRole(
  admin: AdminConfig,
  role: "full" | "readonly",
  suffix: string
): Promise<RoleArtifacts> {
  const descriptor = ROLE_DESCRIPTORS[role];
  const roleName = `${TEST_RESOURCE_PREFIX}${role}-${suffix}`;
  await createRole(roleName, descriptor);
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

interface LayerAResult {
  role: "full" | "readonly";
  outcome: "pass" | "fail";
  detail: string;
}

async function runLayerA(
  role: "full" | "readonly",
  admin: AdminConfig,
  apiKey: CreatedApiKey
): Promise<LayerAResult> {
  const descriptor = ROLE_DESCRIPTORS[role];
  useScopedConfig(admin, apiKey.encoded);

  const probe = {
    cluster: descriptor.cluster,
    index: descriptor.indices.map((i) => ({
      names: i.names,
      privileges: i.privileges,
    })),
    application: descriptor.applications.map((a) => ({
      application: a.application,
      privileges: a.privileges,
      resources: a.resources,
    })),
  };

  try {
    const result = await hasPrivileges(probe);
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
  admin: AdminConfig,
  apiKey: CreatedApiKey,
  fixtures: SeedFixtures
): Promise<{ checkResults: CheckResult[]; observed: ObservedRun[] }> {
  useScopedConfig(admin, apiKey.encoded);
  const observed = await runOpsObserve(role, fixtures);
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
async function countLeftoverTaggedResources(): Promise<LeftoverCounts> {
  let cases = 0;
  let rules = 0;
  try {
    const result = await listCases({ tags: [TEST_TAG], perPage: 1 });
    cases = result.total;
  } catch {
    /* cases API unavailable — leave at 0 */
  }
  try {
    const result = await findRules({
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
  role: RoleName,
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

async function cleanupRoleArtifacts(
  admin: AdminConfig,
  artifacts: RoleArtifacts[],
  quickstartArtifacts: QuickstartArtifacts[],
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
    return;
  }
  useAdminConfig(admin);
  for (const a of artifacts) {
    try {
      await deleteApiKey(a.apiKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate API key ${a.apiKey.id}: ${formatError(err)}`
      );
    }
    try {
      await deleteRole(a.roleName);
    } catch (err) {
      console.warn(
        `  warning: failed to delete role ${a.roleName}: ${formatError(err)}`
      );
    }
  }
  for (const q of quickstartArtifacts) {
    try {
      await deleteApiKey(q.apiKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate API key ${q.apiKey.id}: ${formatError(err)}`
      );
    }
    try {
      await deleteUser(q.username);
    } catch (err) {
      console.warn(
        `  warning: failed to delete user ${q.username}: ${formatError(err)}`
      );
    }
    try {
      await deleteRole(q.companionRoleName);
    } catch (err) {
      console.warn(
        `  warning: failed to delete role ${q.companionRoleName}: ${formatError(err)}`
      );
    }
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const basics = loadAdminBasics();

  // Bootstrap an admin API key via Basic auth. Two reasons:
  //  1. esRequest/kibanaRequest only support `Authorization: ApiKey ...`
  //     and we need an admin-privilege key for seed-fixture queries
  //     (fetchAlerts, listCases, createCase, etc.).
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

  const provisioned: RoleArtifacts[] = [];
  const provisionedQuickstarts: QuickstartArtifacts[] = [];
  let interrupted = false;

  const cleanupBootstrap = async () => {
    try {
      useAdminConfig(admin);
      await deleteApiKey(bootstrapKey.id);
    } catch (err) {
      console.warn(
        `  warning: failed to invalidate bootstrap admin key ${bootstrapKey.id}: ${formatError(err)}`
      );
    }
  };

  const onSignal = () => {
    interrupted = true;
    console.log("\n→ Caught SIGINT, cleaning up before exit…");
    cleanupRoleArtifacts(admin, provisioned, provisionedQuickstarts, opts)
      .then(() => cleanupBootstrap())
      .catch((err) => console.error(`Cleanup error: ${formatError(err)}`))
      .finally(() => process.exit(130));
  };
  process.on("SIGINT", onSignal);

  let exitCode = 0;
  try {
    if (opts.cleanupStale) {
      useAdminConfig(admin);
      console.log(`→ --cleanup-stale: removing leftover ${TEST_RESOURCE_PREFIX}* resources…`);
      await cleanupStaleResources(opts);
    }

    console.log("→ Pre-flight: checking connectivity and seed data…");
    const fixtures = await preflight(admin, opts);
    if (opts.verbose) {
      console.log(`  alertId:     ${fixtures.alertId}`);
      console.log(`  alertIndex:  ${fixtures.alertIndex}`);
      console.log(`  alertRuleId: ${fixtures.alertRuleId}`);
      console.log(`  caseId:      ${fixtures.caseId}`);
      console.log(`  ruleId:      ${fixtures.ruleId ?? "(none — patchRule will skip)"}`);
      console.log(`  suffix:      ${fixtures.suffix}`);
    }

    interface AssertedRun {
      role: AssertedRoleName;
      layerA: LayerAResult | null;
      layerB: CheckResult[];
    }
    const assertedRuns: AssertedRun[] = [];
    const unavailableQuickstarts: UnavailableQuickstart[] = [];

    for (const role of opts.roles) {
      console.log(`\n→ Provisioning role "${role}"…`);
      useAdminConfig(admin);
      let apiKey: CreatedApiKey;
      let layerA: LayerAResult | null = null;
      if (role === "full" || role === "readonly") {
        const artifacts = await provisionRole(admin, role, fixtures.suffix);
        provisioned.push(artifacts);
        apiKey = artifacts.apiKey;
        layerA = await runLayerA(role, admin, artifacts.apiKey);
      } else {
        const result = await provisionQuickstart(admin, role, fixtures.suffix);
        if ("reason" in result) {
          console.warn(`  ! ${role} unavailable: ${result.reason}`);
          unavailableQuickstarts.push(result);
          continue;
        }
        provisionedQuickstarts.push(result);
        apiKey = result.apiKey;
      }
      const { checkResults } = await runLayerB(role, admin, apiKey, fixtures);
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

    if (assertedRuns.length > 0) {
      console.log(
        `\nSummary: ${passed} passed, ${failed} failed, ${skipped} skipped`
      );
    }

    // Surface leftover test resources so the user can clean them up. We
    // query under the admin key to make sure we see everything regardless
    // of which scoped role still has setConfig active.
    useAdminConfig(admin);
    const leftover = await countLeftoverTaggedResources();
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
          admin,
          provisioned,
          provisionedQuickstarts,
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

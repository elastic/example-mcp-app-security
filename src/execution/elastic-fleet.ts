/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { elasticAgentArtifact } from "./elastic-agent.js";

type ElasticAgentPlan = NonNullable<AtomicPlan["instrumentation"]>["elastic_agent"];

type KibanaStatus = {
  version?: { number?: unknown };
};

type FleetServerHost = {
  id?: unknown;
  name?: unknown;
  host_urls?: unknown;
  is_default?: unknown;
};

type FleetOutput = {
  id?: unknown;
  name?: unknown;
  type?: unknown;
  hosts?: unknown;
  is_default?: unknown;
};

type AgentPolicy = {
  id?: unknown;
  name?: unknown;
  revision?: unknown;
  status?: unknown;
  is_default?: unknown;
  has_fleet_server?: unknown;
  is_default_fleet_server?: unknown;
  supports_agentless?: unknown;
  fleet_server_host_id?: unknown;
  data_output_id?: unknown;
  output_id?: unknown;
};

type PackagePolicy = {
  id?: unknown;
  enabled?: unknown;
  package?: { name?: unknown; version?: unknown };
  policy_id?: unknown;
  policy_ids?: unknown;
};

type FleetState = {
  status: KibanaStatus;
  availableAgentVersions: string[];
  fleetHosts: FleetServerHost[];
  outputs: FleetOutput[];
  policies: AgentPolicy[];
  packagePolicies: PackagePolicy[];
};

export type ElasticFleetDiscovery = {
  instrumentation: {
    elastic_agent: ElasticAgentPlan;
  };
  selection: {
    strategy: "default-elastic-defend-policy" | "deterministic-elastic-defend-policy";
    eligible_policy_ids: string[];
    agent_version_strategy: "highest-compatible-published-ga";
    verified_artifact_architectures: ["arm64", "x86_64"];
  };
};

export type EphemeralEnrollmentToken = {
  id: string;
  token: string;
  policyId: string;
  expiresIn: "1h";
};

let configuredElasticEnvironment:
  | { readonly kibanaUrl: string; readonly apiKey: string }
  | undefined;

/**
 * Supply the app's already validated default-cluster credentials to the
 * Atomic tools. Explicit KIBANA_URL / ELASTIC_API_KEY variables still win,
 * which keeps the tools usable outside the integrated app server.
 */
export function configureAtomicElasticEnvironment(
  environment:
    | { readonly kibanaUrl: string; readonly apiKey: string }
    | undefined
): void {
  configuredElasticEnvironment = environment
    ? Object.freeze({ ...environment })
    : undefined;
}

export function getElasticEnvironment(): { kibanaUrl: string; apiKey: string } {
  const rawUrl =
    process.env.KIBANA_URL?.trim() || configuredElasticEnvironment?.kibanaUrl;
  const rawKey =
    process.env.ELASTIC_API_KEY?.trim() || configuredElasticEnvironment?.apiKey;
  if (!rawUrl || !rawKey) {
    throw new Error("KIBANA_URL and ELASTIC_API_KEY are required");
  }
  return {
    kibanaUrl: approvedHttpsUrl(rawUrl, "KIBANA_URL"),
    apiKey: normalizeApiKey(rawKey),
  };
}

export async function discoverElasticFleet(): Promise<ElasticFleetDiscovery> {
  const environment = getElasticEnvironment();
  const state = await loadFleetState(environment);
  const stackVersion = requiredString(state.status.version?.number, "Kibana stack version");
  if (!/^\d+\.\d+\.\d+$/.test(stackVersion)) {
    throw new Error(`Kibana returned unsupported stack version ${stackVersion}`);
  }
  const agentVersion = await selectPublishedAgentVersion(
    stackVersion,
    state.availableAgentVersions
  );

  const endpointByPolicy = new Map<string, PackagePolicy[]>();
  for (const packagePolicy of state.packagePolicies) {
    if (packagePolicy.enabled === false || packagePolicy.package?.name !== "endpoint") continue;
    for (const policyId of packagePolicyPolicyIds(packagePolicy)) {
      const current = endpointByPolicy.get(policyId) ?? [];
      current.push(packagePolicy);
      endpointByPolicy.set(policyId, current);
    }
  }

  const eligible = state.policies
    .filter((policy) => {
      const id = optionalString(policy.id);
      return Boolean(
        id &&
        policy.status === "active" &&
        policy.has_fleet_server !== true &&
        policy.is_default_fleet_server !== true &&
        policy.supports_agentless !== true &&
        endpointByPolicy.has(id)
      );
    })
    .sort((left, right) => {
      const defaultRank = Number(right.is_default === true) - Number(left.is_default === true);
      if (defaultRank !== 0) return defaultRank;
      const nameRank = optionalString(left.name).localeCompare(optionalString(right.name));
      return nameRank || optionalString(left.id).localeCompare(optionalString(right.id));
    });

  if (eligible.length === 0) {
    throw new Error(
      "Fleet has no active, enrollable agent policy containing an enabled Elastic Defend integration"
    );
  }

  const selectedPolicy = eligible[0]!;
  const policyId = requiredString(selectedPolicy.id, "agent policy id");
  const endpointPolicies = endpointByPolicy.get(policyId)!
    .sort((left, right) => optionalString(left.id).localeCompare(optionalString(right.id)));
  const endpointPolicy = endpointPolicies[0]!;

  const fleetHost = selectFleetHost(state.fleetHosts, optionalString(selectedPolicy.fleet_server_host_id));
  const output = selectElasticsearchOutput(
    state.outputs,
    optionalString(selectedPolicy.data_output_id) || optionalString(selectedPolicy.output_id)
  );

  const fleetUrl = firstApprovedUrl(fleetHost.host_urls, "Fleet Server host");
  const elasticsearchUrl = firstApprovedUrl(output.hosts, "Elasticsearch output");
  const eligibleIds = eligible.map((policy) => requiredString(policy.id, "eligible policy id"));

  return {
    instrumentation: {
      elastic_agent: {
        stack_version: stackVersion,
        version: agentVersion,
        kibana_url: environment.kibanaUrl,
        fleet_url: fleetUrl,
        fleet_server_host_id: requiredString(fleetHost.id, "Fleet Server host id"),
        agent_policy_id: policyId,
        agent_policy_name: requiredString(selectedPolicy.name, "agent policy name"),
        agent_policy_revision: requiredPositiveInteger(
          selectedPolicy.revision,
          "agent policy revision"
        ),
        elastic_defend_package_policy_id: requiredString(
          endpointPolicy.id,
          "Elastic Defend package policy id"
        ),
        elastic_defend_package_version: requiredString(
          endpointPolicy.package?.version,
          "Elastic Defend package version"
        ),
        elasticsearch_output_id: requiredString(output.id, "Elasticsearch output id"),
        elasticsearch_url: elasticsearchUrl,
        insecure: false,
        health_timeout_seconds: 300,
      },
    },
    selection: {
      strategy:
        selectedPolicy.is_default === true
          ? "default-elastic-defend-policy"
          : "deterministic-elastic-defend-policy",
      eligible_policy_ids: eligibleIds,
      agent_version_strategy: "highest-compatible-published-ga",
      verified_artifact_architectures: ["arm64", "x86_64"],
    },
  };
}

export async function validateApprovedElasticConfiguration(
  plan: ElasticAgentPlan
): Promise<Record<string, unknown>> {
  const environment = getElasticEnvironment();
  if (environment.kibanaUrl !== normalizeUrl(plan.kibana_url)) {
    throw new Error("KIBANA_URL does not match the digest-approved Kibana URL");
  }
  const state = await loadFleetState(environment);
  const stackVersion = requiredString(state.status.version?.number, "Kibana stack version");
  if (stackVersion !== plan.stack_version) {
    throw new Error(
      `Elastic stack version drift: approved ${plan.stack_version}, current ${stackVersion}`
    );
  }
  if (!isAgentVersionCompatible(stackVersion, plan.version)) {
    throw new Error(
      `Approved Elastic Agent ${plan.version} is not compatible with stack ${stackVersion}`
    );
  }
  if (!state.availableAgentVersions.includes(plan.version)) {
    throw new Error(`Approved Elastic Agent ${plan.version} is no longer offered by Fleet`);
  }
  if (!(await hasPublishedArtifacts(plan.version))) {
    throw new Error(
      `Approved Elastic Agent ${plan.version} no longer has published GA Linux artifacts for arm64 and x86_64`
    );
  }

  const fleetHost = state.fleetHosts.find(
    (item) => optionalString(item.id) === plan.fleet_server_host_id
  );
  if (!fleetHost || !approvedUrls(fleetHost.host_urls).includes(normalizeUrl(plan.fleet_url))) {
    throw new Error("Approved Fleet Server host is missing or changed");
  }

  const policy = state.policies.find((item) => optionalString(item.id) === plan.agent_policy_id);
  if (!policy || policy.status !== "active") {
    throw new Error("Approved Fleet agent policy is missing or inactive");
  }
  if (
    requiredString(policy.name, "agent policy name") !== plan.agent_policy_name ||
    requiredPositiveInteger(policy.revision, "agent policy revision") !== plan.agent_policy_revision
  ) {
    throw new Error("Approved Fleet agent policy name or revision changed");
  }
  const currentFleetHostId = optionalString(policy.fleet_server_host_id);
  if (
    (currentFleetHostId && currentFleetHostId !== plan.fleet_server_host_id) ||
    (!currentFleetHostId && fleetHost.is_default !== true)
  ) {
    throw new Error("Approved Fleet agent policy now resolves to a different Fleet Server host");
  }

  const endpointPolicy = state.packagePolicies.find(
    (item) => optionalString(item.id) === plan.elastic_defend_package_policy_id
  );
  if (
    !endpointPolicy ||
    endpointPolicy.enabled === false ||
    endpointPolicy.package?.name !== "endpoint" ||
    endpointPolicy.package?.version !== plan.elastic_defend_package_version ||
    !packagePolicyPolicyIds(endpointPolicy).includes(plan.agent_policy_id)
  ) {
    throw new Error("Approved Elastic Defend package policy is missing or changed");
  }

  const output = state.outputs.find(
    (item) => optionalString(item.id) === plan.elasticsearch_output_id
  );
  if (
    !output ||
    output.type !== "elasticsearch" ||
    !approvedUrls(output.hosts).includes(normalizeUrl(plan.elasticsearch_url))
  ) {
    throw new Error("Approved Elasticsearch Fleet output is missing or changed");
  }
  const currentOutputId =
    optionalString(policy.data_output_id) || optionalString(policy.output_id);
  if (
    (currentOutputId && currentOutputId !== plan.elasticsearch_output_id) ||
    (!currentOutputId && output.is_default !== true)
  ) {
    throw new Error("Approved Fleet agent policy now resolves to a different Elasticsearch output");
  }

  return {
    ok: true,
    stack_version: stackVersion,
    agent_version: plan.version,
    fleet_server_host_id: plan.fleet_server_host_id,
    agent_policy_id: plan.agent_policy_id,
    agent_policy_revision: plan.agent_policy_revision,
    elastic_defend_package_policy_id: plan.elastic_defend_package_policy_id,
    elasticsearch_output_id: plan.elasticsearch_output_id,
  };
}

export async function createEphemeralEnrollmentToken(
  plan: ElasticAgentPlan,
  runId: string
): Promise<EphemeralEnrollmentToken> {
  const environment = getElasticEnvironment();
  if (environment.kibanaUrl !== normalizeUrl(plan.kibana_url)) {
    throw new Error("KIBANA_URL does not match the digest-approved Kibana URL");
  }
  const response = await kibanaRequest(
    environment,
    "api/fleet/enrollment_api_keys",
    {
      method: "POST",
      body: {
        policy_id: plan.agent_policy_id,
        name: `atomic-${runId.replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 80)}-${Date.now()}`,
        expiration: "1h",
      },
      secretResponse: true,
    }
  ) as { item?: { id?: unknown; api_key?: unknown; policy_id?: unknown } };
  const id = requiredString(response.item?.id, "enrollment token id");
  const token = requiredString(response.item?.api_key, "enrollment token secret");
  const policyId = requiredString(response.item?.policy_id, "enrollment token policy id");
  if (policyId !== plan.agent_policy_id) {
    await revokeEnrollmentToken(id).catch(() => undefined);
    throw new Error("Kibana created an enrollment token for the wrong policy");
  }
  return { id, token, policyId, expiresIn: "1h" };
}

export async function revokeEnrollmentToken(tokenId: string): Promise<Record<string, unknown>> {
  const environment = getElasticEnvironment();
  const response = await kibanaRequest(
    environment,
    `api/fleet/enrollment_api_keys/${encodeURIComponent(tokenId)}?forceDelete=true`,
    { method: "DELETE" }
  ) as { action?: unknown };
  if (response.action !== "deleted") {
    throw new Error(`Kibana did not confirm revocation of enrollment token ${tokenId}`);
  }
  return { ok: true, id: tokenId, action: "deleted" };
}

async function loadFleetState(
  environment: ReturnType<typeof getElasticEnvironment>
): Promise<FleetState> {
  const [status, versions, hosts, outputs, policies, packagePolicies] = await Promise.all([
    kibanaRequest(environment, "api/status"),
    kibanaRequest(environment, "api/fleet/agents/available_versions"),
    kibanaRequest(environment, "api/fleet/fleet_server_hosts?perPage=10000"),
    kibanaRequest(environment, "api/fleet/outputs"),
    kibanaRequest(environment, "api/fleet/agent_policies?perPage=10000"),
    kibanaRequest(environment, "api/fleet/package_policies?perPage=10000"),
  ]);
  return {
    status: status as KibanaStatus,
    availableAgentVersions: responseItems(versions, "available Elastic Agent versions")
      .map((value) => requiredString(value, "available Elastic Agent version")),
    fleetHosts: responseItems(hosts, "Fleet Server hosts") as FleetServerHost[],
    outputs: responseItems(outputs, "Fleet outputs") as FleetOutput[],
    policies: responseItems(policies, "Fleet agent policies") as AgentPolicy[],
    packagePolicies: responseItems(packagePolicies, "Fleet package policies") as PackagePolicy[],
  };
}

export async function selectPublishedAgentVersion(
  stackVersion: string,
  availableVersions: readonly string[]
): Promise<string> {
  const candidates = [...new Set(availableVersions)]
    .filter((version) => /^\d+\.\d+\.\d+$/.test(version))
    .filter((version) => isAgentVersionCompatible(stackVersion, version))
    .sort(compareSemverDescending)
    .slice(0, 50);
  for (const candidate of candidates) {
    if (await hasPublishedArtifacts(candidate)) return candidate;
  }
  throw new Error(
    `Fleet offers no compatible GA Elastic Agent with published Linux arm64 and x86_64 artifacts for stack ${stackVersion}`
  );
}

async function hasPublishedArtifacts(version: string): Promise<boolean> {
  const artifacts = [
    elasticAgentArtifact(version, "arm64"),
    elasticAgentArtifact(version, "x86_64"),
  ];
  const urls = artifacts.flatMap((artifact) => [artifact.url, artifact.checksumUrl]);
  const results = await Promise.all(
    urls.map(async (url) => {
      try {
        const response = await fetch(url, {
          method: "HEAD",
          redirect: "follow",
          signal: AbortSignal.timeout(15_000),
        });
        return response.ok;
      } catch {
        return false;
      }
    })
  );
  return results.every(Boolean);
}

function isAgentVersionCompatible(stackVersion: string, agentVersion: string): boolean {
  const stack = parseSemver(stackVersion);
  const agent = parseSemver(agentVersion);
  return stack.major === agent.major && agent.minor <= stack.minor;
}

function compareSemverDescending(left: string, right: string): number {
  const a = parseSemver(left);
  const b = parseSemver(right);
  return b.major - a.major || b.minor - a.minor || b.patch - a.patch;
}

function parseSemver(value: string): { major: number; minor: number; patch: number } {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value);
  if (!match) throw new Error(`Invalid semantic version ${value}`);
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

async function kibanaRequest(
  environment: ReturnType<typeof getElasticEnvironment>,
  requestPath: string,
  options: {
    method?: "GET" | "POST" | "DELETE";
    body?: Record<string, unknown>;
    secretResponse?: boolean;
  } = {}
): Promise<unknown> {
  const url = new URL(requestPath, `${environment.kibanaUrl}/`);
  const method = options.method ?? "GET";
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `ApiKey ${environment.apiKey}`,
      accept: "application/json",
      ...(method === "GET" ? {} : { "content-type": "application/json", "kbn-xsrf": "true" }),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const body = options.secretResponse ? "[REDACTED]" : (await response.text()).slice(0, 2_000);
    throw new Error(`Kibana API ${method} ${url.pathname} failed (${response.status}): ${body}`);
  }
  return response.json();
}

function selectFleetHost(hosts: FleetServerHost[], requestedId: string): FleetServerHost {
  const selected = requestedId
    ? hosts.find((item) => optionalString(item.id) === requestedId)
    : hosts.find((item) => item.is_default === true) ??
      [...hosts].sort((left, right) => optionalString(left.id).localeCompare(optionalString(right.id)))[0];
  if (!selected) throw new Error("Fleet has no Fleet Server host configured");
  return selected;
}

function selectElasticsearchOutput(outputs: FleetOutput[], requestedId: string): FleetOutput {
  const elasticsearchOutputs = outputs.filter((item) => item.type === "elasticsearch");
  const selected = requestedId
    ? elasticsearchOutputs.find((item) => optionalString(item.id) === requestedId)
    : elasticsearchOutputs.find((item) => item.is_default === true) ??
      [...elasticsearchOutputs].sort((left, right) =>
        optionalString(left.id).localeCompare(optionalString(right.id))
      )[0];
  if (!selected) throw new Error("Fleet has no Elasticsearch output configured for the policy");
  return selected;
}

function packagePolicyPolicyIds(packagePolicy: PackagePolicy): string[] {
  const ids = Array.isArray(packagePolicy.policy_ids)
    ? packagePolicy.policy_ids.filter((value): value is string => typeof value === "string")
    : [];
  const legacy = optionalString(packagePolicy.policy_id);
  if (legacy && !ids.includes(legacy)) ids.push(legacy);
  return ids;
}

function responseItems(value: unknown, label: string): unknown[] {
  if (!value || typeof value !== "object" || !Array.isArray((value as { items?: unknown }).items)) {
    throw new Error(`${label} response has no items array`);
  }
  return (value as { items: unknown[] }).items;
}

function firstApprovedUrl(value: unknown, label: string): string {
  const urls = approvedUrls(value);
  if (urls.length === 0) throw new Error(`${label} has no credential-free HTTPS URL`);
  return urls[0]!;
}

function approvedUrls(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => {
      try {
        return approvedHttpsUrl(item, "Elastic endpoint");
      } catch {
        return undefined;
      }
    })
    .filter((item): item is string => Boolean(item));
}

function approvedHttpsUrl(value: string, label: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error(`${label} must be a credential-free HTTPS URL`);
  }
  parsed.hash = "";
  parsed.search = "";
  return normalizeUrl(parsed.toString());
}

function normalizeUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

function normalizeApiKey(value: string): string {
  const unprefixed = value.replace(/^ApiKey\s+/i, "").trim();
  return unprefixed.includes(":")
    ? Buffer.from(unprefixed, "utf8").toString("base64")
    : unprefixed;
}

function optionalString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function requiredString(value: unknown, label: string): string {
  const parsed = optionalString(value).trim();
  if (!parsed) throw new Error(`Missing ${label}`);
  return parsed;
}

function requiredPositiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(`Missing or invalid ${label}`);
  }
  return value;
}

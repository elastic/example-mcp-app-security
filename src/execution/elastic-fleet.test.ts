/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  configureAtomicElasticEnvironment,
  createEphemeralEnrollmentToken,
  discoverElasticFleet,
  getElasticEnvironment,
  revokeEnrollmentToken,
  validateApprovedElasticConfiguration,
} from "./elastic-fleet.js";

const originalKibanaUrl = process.env.KIBANA_URL;
const originalApiKey = process.env.ELASTIC_API_KEY;

describe("minimal-input Elastic Fleet control plane", () => {
  beforeEach(() => {
    process.env.KIBANA_URL = "https://kibana.example";
    process.env.ELASTIC_API_KEY = "encoded-api-key";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    configureAtomicElasticEnvironment(undefined);
    restoreEnvironment("KIBANA_URL", originalKibanaUrl);
    restoreEnvironment("ELASTIC_API_KEY", originalApiKey);
  });

  it("reuses the app's validated default-cluster credentials", () => {
    delete process.env.KIBANA_URL;
    delete process.env.ELASTIC_API_KEY;
    configureAtomicElasticEnvironment({
      kibanaUrl: "https://configured-kibana.example",
      apiKey: "configured-api-key",
    });

    expect(getElasticEnvironment()).toEqual({
      kibanaUrl: "https://configured-kibana.example",
      apiKey: "configured-api-key",
    });
    expect(process.env.ELASTIC_API_KEY).toBeUndefined();
  });

  it("discovers and binds the default eligible Elastic Defend policy", async () => {
    const requests: Array<{ url: URL; method: string; authorization: string | null }> = [];
    vi.stubGlobal("fetch", fleetFetch(requests));

    const discovered = await discoverElasticFleet();

    expect(discovered.instrumentation.elastic_agent).toMatchObject({
      stack_version: "9.7.0",
      version: "9.6.4",
      kibana_url: "https://kibana.example",
      fleet_url: "https://fleet.example:8220",
      fleet_server_host_id: "fleet-default",
      agent_policy_id: "policy-defend",
      agent_policy_name: "Linux Defend",
      agent_policy_revision: 4,
      elastic_defend_package_policy_id: "endpoint-policy",
      elastic_defend_package_version: "9.7.0",
      elasticsearch_output_id: "output-default",
      elasticsearch_url: "https://elasticsearch.example:9200",
      insecure: false,
      health_timeout_seconds: 300,
    });
    expect(discovered.selection.strategy).toBe("default-elastic-defend-policy");
    expect(discovered.selection.agent_version_strategy).toBe(
      "highest-compatible-published-ga"
    );
    expect(
      requests
        .filter((request) => request.url.hostname === "kibana.example")
        .every((request) => request.authorization === "ApiKey encoded-api-key")
    ).toBe(true);
    expect(
      requests
        .filter((request) => request.url.hostname === "artifacts.elastic.co")
        .every((request) => request.authorization === null)
    ).toBe(true);
  });

  it("detects drift before provisioning", async () => {
    vi.stubGlobal("fetch", fleetFetch([]));
    const plan = (await discoverElasticFleet()).instrumentation.elastic_agent;
    await expect(validateApprovedElasticConfiguration(plan)).resolves.toMatchObject({
      ok: true,
      agent_policy_id: "policy-defend",
    });

    await expect(
      validateApprovedElasticConfiguration({ ...plan, agent_policy_revision: 5 })
    ).rejects.toThrow("revision changed");
  });

  it("creates and force-deletes a short-lived token without putting the secret in requests", async () => {
    const requests: Array<{ url: URL; method: string; authorization: string | null; body?: string }> = [];
    vi.stubGlobal("fetch", fleetFetch(requests));
    const plan = (await discoverElasticFleet()).instrumentation.elastic_agent;

    const token = await createEphemeralEnrollmentToken(plan, "example-run");
    expect(token).toEqual({
      id: "temporary-token-id",
      token: "temporary-token-secret",
      policyId: "policy-defend",
      expiresIn: "1h",
    });
    await expect(revokeEnrollmentToken(token.id)).resolves.toEqual({
      ok: true,
      id: "temporary-token-id",
      action: "deleted",
    });

    const create = requests.find((request) => request.method === "POST")!;
    const remove = requests.find((request) => request.method === "DELETE")!;
    expect(JSON.parse(create.body ?? "{}")).toMatchObject({
      policy_id: "policy-defend",
      expiration: "1h",
    });
    expect(create.body).not.toContain("temporary-token-secret");
    expect(remove.url.searchParams.get("forceDelete")).toBe("true");
  });
});

function fleetFetch(
  requests: Array<{
    url: URL;
    method: string;
    authorization: string | null;
    body?: string;
  }>
) {
  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    requests.push({
      url,
      method,
      authorization: headers.get("authorization"),
      body: typeof init?.body === "string" ? init.body : undefined,
    });

    if (url.hostname === "artifacts.elastic.co" && method === "HEAD") {
      return new Response(null, { status: url.pathname.includes("9.6.4") ? 200 : 404 });
    }
    if (url.pathname === "/api/status") return json({ version: { number: "9.7.0" } });
    if (url.pathname === "/api/fleet/agents/available_versions") {
      return json({ items: ["9.7.0", "9.7.0-SNAPSHOT", "9.6.4", "8.19.10"] });
    }
    if (url.pathname === "/api/fleet/fleet_server_hosts") {
      return json({
        items: [
          {
            id: "fleet-default",
            name: "Default Fleet",
            host_urls: ["https://fleet.example:8220"],
            is_default: true,
          },
        ],
      });
    }
    if (url.pathname === "/api/fleet/outputs") {
      return json({
        items: [
          {
            id: "output-default",
            name: "Default output",
            type: "elasticsearch",
            hosts: ["https://elasticsearch.example:9200"],
            is_default: true,
          },
        ],
      });
    }
    if (url.pathname === "/api/fleet/agent_policies") {
      return json({
        items: [
          {
            id: "policy-defend",
            name: "Linux Defend",
            revision: 4,
            status: "active",
            is_default: true,
            fleet_server_host_id: "fleet-default",
            data_output_id: "output-default",
          },
          {
            id: "policy-without-defend",
            name: "System only",
            revision: 2,
            status: "active",
          },
        ],
      });
    }
    if (url.pathname === "/api/fleet/package_policies") {
      return json({
        items: [
          {
            id: "endpoint-policy",
            enabled: true,
            package: { name: "endpoint", version: "9.7.0" },
            policy_ids: ["policy-defend"],
          },
        ],
      });
    }
    if (url.pathname === "/api/fleet/enrollment_api_keys" && method === "POST") {
      return json({
        action: "created",
        item: {
          id: "temporary-token-id",
          api_key: "temporary-token-secret",
          policy_id: "policy-defend",
        },
      });
    }
    if (
      url.pathname === "/api/fleet/enrollment_api_keys/temporary-token-id" &&
      method === "DELETE"
    ) {
      return json({ action: "deleted" });
    }
    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  });
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

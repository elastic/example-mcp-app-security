/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { esRequest } from "../../src/elastic/client.js";
import type { RoleDescriptor } from "./roles.js";

export interface CreatedApiKey {
  id: string;
  name: string;
  /** Base64 string used as the `ApiKey` header value. */
  encoded: string;
}

export interface BasicAuth {
  elasticsearchUrl: string;
  username: string;
  password: string;
}

/**
 * POST /_security/api_key authenticated with Basic auth — bypasses the
 * "derived API key" restriction that prevents API-key-authenticated
 * callers from creating new keys with explicit role_descriptors.
 *
 * Used both for the bootstrap admin key (with `role_descriptors: {}` =
 * inherit owner privileges) and for the per-role scoped keys (with
 * explicit `role_descriptors`).
 */
async function basicAuthCreateApiKey(
  auth: BasicAuth,
  body: Record<string, unknown>
): Promise<{ id: string; name: string; encoded: string }> {
  const url = auth.elasticsearchUrl.replace(/\/$/, "") + "/_security/api_key";
  const credentials = Buffer.from(`${auth.username}:${auth.password}`).toString("base64");
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Elasticsearch ${res.status}: ${text}`);
  }
  return (await res.json()) as { id: string; name: string; encoded: string };
}

/**
 * Bootstraps an admin API key by authenticating as the admin user
 * (basic auth) and creating a key that inherits the user's privileges.
 * Used as the `ELASTICSEARCH_API_KEY` for everything that goes through
 * esRequest/kibanaRequest during the runner.
 */
export async function bootstrapAdminApiKey(
  auth: BasicAuth,
  name: string
): Promise<CreatedApiKey> {
  return basicAuthCreateApiKey(auth, { name, role_descriptors: {} });
}

export interface HasPrivilegesProbe {
  cluster?: string[];
  index?: Array<{ names: string[]; privileges: string[] }>;
  application?: Array<{
    application: string;
    privileges: string[];
    resources: string[];
  }>;
}

export interface HasPrivilegesResult {
  has_all_requested: boolean;
  cluster: Record<string, boolean>;
  index: Record<string, Record<string, boolean>>;
  application: Record<string, Record<string, Record<string, boolean>>>;
}

export async function createRole(
  name: string,
  descriptor: RoleDescriptor
): Promise<{ created: boolean }> {
  const result = await esRequest<{ role: { created: boolean } }>(
    `/_security/role/${encodeURIComponent(name)}`,
    {
      method: "PUT",
      body: descriptor,
    }
  );
  return { created: result.role?.created ?? true };
}

export async function deleteRole(name: string): Promise<{ found: boolean }> {
  try {
    return await esRequest<{ found: boolean }>(
      `/_security/role/${encodeURIComponent(name)}`,
      { method: "DELETE" }
    );
  } catch (err) {
    if (err instanceof Error && err.message.includes("Elasticsearch 404")) {
      return { found: false };
    }
    throw err;
  }
}

export async function createApiKey(
  auth: BasicAuth,
  name: string,
  roleName: string,
  descriptor: RoleDescriptor
): Promise<CreatedApiKey> {
  // Must use Basic auth: derived API keys (created when authenticated
  // with another API key) are not allowed to specify explicit
  // role_descriptors per ES security policy.
  return basicAuthCreateApiKey(auth, {
    name,
    role_descriptors: { [roleName]: descriptor },
  });
}

export async function deleteApiKey(
  id: string
): Promise<{ invalidated_api_keys: string[] }> {
  return esRequest<{ invalidated_api_keys: string[] }>(
    "/_security/api_key",
    {
      method: "DELETE",
      body: { ids: [id] },
    }
  );
}

export async function hasPrivileges(
  probe: HasPrivilegesProbe
): Promise<HasPrivilegesResult> {
  return esRequest<HasPrivilegesResult>("/_security/user/_has_privileges", {
    method: "POST",
    body: probe,
  });
}

/**
 * List API keys whose name matches the given prefix. Used by --cleanup-stale.
 * Only returns active (non-invalidated) keys.
 */
export async function listApiKeysByPrefix(
  prefix: string
): Promise<{ id: string; name: string }[]> {
  const result = await esRequest<{
    api_keys: Array<{
      id: string;
      name: string;
      invalidated: boolean;
    }>;
  }>("/_security/api_key", {
    method: "GET",
    params: { name: `${prefix}*` },
  });
  return (result.api_keys || [])
    .filter((k) => !k.invalidated)
    .map((k) => ({ id: k.id, name: k.name }));
}

/**
 * List role names matching a prefix. Used by --cleanup-stale.
 */
export async function listRolesByPrefix(prefix: string): Promise<string[]> {
  const result = await esRequest<Record<string, unknown>>("/_security/role");
  return Object.keys(result).filter((name) => name.startsWith(prefix));
}

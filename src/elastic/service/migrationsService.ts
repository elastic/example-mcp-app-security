/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaClient } from "../kibana-client/index.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const SIEM_MIGRATIONS_API_BASE = "/internal/siem_migrations";

/**
 * Per-request headers required by the Kibana internal SIEM migrations API.
 * `x-elastic-internal-origin: Kibana` is pre-baked into `KibanaClient`;
 * only the versioning header needs to be added on each call.
 */
const MIGRATION_HEADERS = {
  "elastic-api-version": "2023-10-31",
} as const;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export interface SiemMigration {
  id: string;
  name: string;
  /** Lifecycle status of the migration. */
  status: "ready" | "running" | "finished" | "error";
  created_at: string;
  last_updated_at: string;
  rules: {
    total: number;
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    installable: number;
    installed: number;
    partially_translated: number;
    untranslatable: number;
  };
}

export interface TranslatedRule {
  id: string;
  migration_id: string;
  status: "pending" | "processing" | "completed" | "failed";
  translation_result?: "full" | "partial" | "untranslatable";
  elastic_rule?: Record<string, unknown>;
  original_rule: Record<string, unknown>;
  comments?: string[];
}

export interface MigrationResource {
  type: "macro" | "lookup";
  name: string;
  content: string;
}

export interface MigrationStats {
  id: string;
  status: SiemMigration["status"];
  rules: SiemMigration["rules"];
}

export interface ListTranslatedRulesOptions {
  readonly page?: number;
  readonly perPage?: number;
  readonly filter?: string;
}

export interface ListTranslatedRulesResult {
  data: TranslatedRule[];
  total: number;
}

export interface InstallRulesOptions {
  /** Specific rule IDs to install; omit to install all installable rules. */
  ids?: string[];
}

export interface InstallRulesResult {
  installed: number;
  failed: number;
}

// ---------------------------------------------------------------------------
// Typed error
// ---------------------------------------------------------------------------

/**
 * Thrown by every {@link MigrationsService} method on a non-2xx response.
 *
 * The Kibana client's response interceptor formats AxiosErrors as
 * `"Kibana [<cluster>] <status>: <body>"` before they reach here, so
 * `status` is extracted from that message when available.
 */
export class MigrationApiError extends Error {
  readonly status: number;
  readonly path: string;

  constructor(path: string, cause: unknown) {
    const causeMsg = cause instanceof Error ? cause.message : String(cause);
    // Match the Kibana client error format: "Kibana [name] STATUS: detail"
    const statusMatch = causeMsg.match(/\b([1-5]\d{2})\b/);
    const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;

    super(`SIEM Migrations API error on ${path}: ${causeMsg}`);
    this.name = "MigrationApiError";
    this.status = status;
    this.path = path;
    if (cause instanceof Error) {
      this.cause = cause;
    }
  }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

interface MigrationsServiceOptions {
  readonly kibanaClient: KibanaClient;
}

/**
 * Thin wrapper over the 14 `/internal/siem_migrations/*` Kibana routes.
 *
 * Every method adds `elastic-api-version: 2023-10-31`; the underlying
 * {@link KibanaClient} supplies `x-elastic-internal-origin: Kibana` and
 * authentication on every request. Non-2xx responses are re-thrown as
 * {@link MigrationApiError}.
 */
export class MigrationsService {
  private readonly client: KibanaClient;

  constructor(options: MigrationsServiceOptions) {
    this.client = options.kibanaClient;
  }

  // ── Migration lifecycle ──────────────────────────────────────────────────

  /** POST /internal/siem_migrations/rules */
  async createMigration(name: string): Promise<{ migration_id: string }> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules`;
    try {
      const { data } = await this.client.post<{ migration_id: string }>(
        path,
        { name },
        { headers: MIGRATION_HEADERS }
      );
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** GET /internal/siem_migrations/rules */
  async listMigrations(): Promise<SiemMigration[]> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules`;
    try {
      const { data } = await this.client.get<SiemMigration[]>(path, {
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** GET /internal/siem_migrations/rules/:migrationId */
  async getMigration(migrationId: string): Promise<SiemMigration> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}`;
    try {
      const { data } = await this.client.get<SiemMigration>(path, {
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** DELETE /internal/siem_migrations/rules/:migrationId */
  async deleteMigration(migrationId: string): Promise<void> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}`;
    try {
      await this.client.delete(path, { headers: MIGRATION_HEADERS });
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  // ── Splunk rule upload ───────────────────────────────────────────────────

  /** POST /internal/siem_migrations/rules/:migrationId/rules */
  async uploadRules(
    migrationId: string,
    rules: Record<string, unknown>[]
  ): Promise<{ total: number }> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/rules`;
    try {
      const { data } = await this.client.post<{ total: number }>(
        path,
        rules,
        { headers: MIGRATION_HEADERS }
      );
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  // ── Translated rules ─────────────────────────────────────────────────────

  /** GET /internal/siem_migrations/rules/:migrationId/rules */
  async getTranslatedRules(
    migrationId: string,
    options: ListTranslatedRulesOptions = {}
  ): Promise<ListTranslatedRulesResult> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/rules`;
    const params: Record<string, string> = {
      page: String(options.page ?? 1),
      per_page: String(options.perPage ?? 20),
    };
    if (options.filter) params.filter = options.filter;

    try {
      const { data } = await this.client.get<ListTranslatedRulesResult>(path, {
        params,
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** GET /internal/siem_migrations/rules/:migrationId/rules/:ruleId */
  async getTranslatedRule(
    migrationId: string,
    ruleId: string
  ): Promise<TranslatedRule> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/rules/${ruleId}`;
    try {
      const { data } = await this.client.get<TranslatedRule>(path, {
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** PUT /internal/siem_migrations/rules/:migrationId/rules/:ruleId */
  async updateTranslatedRule(
    migrationId: string,
    ruleId: string,
    updates: Partial<Pick<TranslatedRule, "elastic_rule" | "translation_result" | "comments">>
  ): Promise<TranslatedRule> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/rules/${ruleId}`;
    try {
      const { data } = await this.client.put<TranslatedRule>(path, updates, {
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  // ── Translation control ──────────────────────────────────────────────────

  /** POST /internal/siem_migrations/rules/:migrationId/start */
  async startTranslation(migrationId: string): Promise<void> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/start`;
    try {
      await this.client.post(path, {}, { headers: MIGRATION_HEADERS });
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** POST /internal/siem_migrations/rules/:migrationId/stop */
  async stopTranslation(migrationId: string): Promise<void> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/stop`;
    try {
      await this.client.post(path, {}, { headers: MIGRATION_HEADERS });
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  // ── Resources ────────────────────────────────────────────────────────────

  /** GET /internal/siem_migrations/resources/:migrationId */
  async getResources(migrationId: string): Promise<MigrationResource[]> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/resources/${migrationId}`;
    try {
      const { data } = await this.client.get<MigrationResource[]>(path, {
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  /** POST /internal/siem_migrations/resources/:migrationId */
  async upsertResources(
    migrationId: string,
    resources: MigrationResource[]
  ): Promise<void> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/resources/${migrationId}`;
    try {
      await this.client.post(path, resources, { headers: MIGRATION_HEADERS });
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  // ── Installation ─────────────────────────────────────────────────────────

  /** POST /internal/siem_migrations/rules/:migrationId/install */
  async installRules(
    migrationId: string,
    options: InstallRulesOptions = {}
  ): Promise<InstallRulesResult> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/install`;
    try {
      const { data } = await this.client.post<InstallRulesResult>(
        path,
        options.ids ? { ids: options.ids } : {},
        { headers: MIGRATION_HEADERS }
      );
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }

  // ── Stats ────────────────────────────────────────────────────────────────

  /** GET /internal/siem_migrations/rules/:migrationId/stats */
  async getStats(migrationId: string): Promise<MigrationStats> {
    const path = `${SIEM_MIGRATIONS_API_BASE}/rules/${migrationId}/stats`;
    try {
      const { data } = await this.client.get<MigrationStats>(path, {
        headers: MIGRATION_HEADERS,
      });
      return data;
    } catch (err) {
      throw new MigrationApiError(path, err);
    }
  }
}

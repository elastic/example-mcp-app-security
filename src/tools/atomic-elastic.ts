/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  discoverElasticFleet,
  getElasticEnvironment,
} from "../execution/elastic-fleet.js";
import { publishAtomicRunResults } from "../execution/elastic-results.js";
import {
  createAtomicRunStore,
  type AtomicQueryPlan,
  type AtomicCoverageRecord,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const elasticSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("discover"),
    run_id: z.string().min(1),
  }),
  z.object({
    action: z.literal("probe"),
    run_id: z.string().min(1),
    test_guid: z.string().uuid(),
    layer: z.enum(["raw", "alerts"]),
    start: z.string().datetime(),
    end: z.string().datetime(),
    timestamp_field: z.string().regex(/^[A-Za-z0-9_.@-]+$/).default("@timestamp"),
  }),
  z.object({
    action: z.literal("verify"),
    run_id: z.string().min(1),
    test_guid: z.string().uuid(),
    start: z.string().datetime(),
    end: z.string().datetime(),
    timestamp_field: z.string().regex(/^[A-Za-z0-9_.@-]+$/).default("@timestamp"),
  }),
  z.object({
    action: z.literal("publish_results"),
    run_id: z.string().min(1),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
  }),
]);

const elasticToolSchema = z.object({
  action: z.enum(["discover", "probe", "verify", "publish_results"]),
  run_id: z.string().min(1),
  campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
  test_guid: z.string().uuid().optional(),
  layer: z.enum(["raw", "alerts"]).optional(),
  start: z.string().datetime().optional(),
  end: z.string().datetime().optional(),
  timestamp_field: z.string().regex(/^[A-Za-z0-9_.@-]+$/).default("@timestamp"),
});

export function registerAtomicElasticTool(
  server: McpServer,
  store = createAtomicRunStore()
): void {
  server.registerTool(
    "atomic-elastic",
    {
      title: "Atomic Elastic Coverage",
      description:
        "Discover a minimal-input Elastic Fleet configuration during planning, execute only the raw-event and alert count queries embedded in the digest-approved plan, or publish terminal per-GUID outcome documents to the discovered Elasticsearch output. It reuses the app's default Elastic cluster credentials, with KIBANA_URL and ELASTIC_API_KEY available as explicit overrides. Publishing is retry-safe through deterministic document IDs and a local NDJSON outbox.",
      inputSchema: elasticToolSchema,
    },
    async (input) => {
      try {
        const parsed = elasticSchema.parse(input);
        if (parsed.action === "discover") {
          store.assertPhase(parsed.run_id, ["planning", "awaiting_approval"]);
          return textResult({ ok: true, ...(await discoverElasticFleet()) });
        }
        const loaded = store.getLoaded(parsed.run_id);
        if (!loaded.plan) return textResult({ error: "No approved plan is stored" }, true);
        if (parsed.action === "publish_results") {
          return textResult(
            await publishAtomicRunResults(loaded, { campaignId: parsed.campaign_id })
          );
        }
        const test = store.getApprovedTest(parsed.run_id, parsed.test_guid);
        if (parsed.action === "probe") {
          store.assertPhase(parsed.run_id, ["verifying", "covering"]);
          const query = test.telemetry?.[parsed.layer];
          if (!query) {
            return textResult(
              { error: `No ${parsed.layer} query is bound into the approved test plan` },
              true
            );
          }
          const count = await elasticCount(
            query,
            parsed.start,
            parsed.end,
            parsed.timestamp_field,
            loaded.plan.instrumentation?.elastic_agent.elasticsearch_url
          );
          return textResult({ ok: true, layer: parsed.layer, count });
        }

        store.assertPhase(parsed.run_id, ["covering"]);
        const rawQuery = test.telemetry?.raw;
        const alertQuery = test.telemetry?.alerts;
        if (!rawQuery || !alertQuery) {
          return textResult(
            {
              error:
                "verify needs both telemetry.raw and telemetry.alerts in the approved plan. Otherwise use the relevant hunt/rule tools and record_coverage manually.",
            },
            true
          );
        }
        const [rawCount, alertCount] = await Promise.all([
          elasticCount(
            rawQuery,
            parsed.start,
            parsed.end,
            parsed.timestamp_field,
            loaded.plan.instrumentation?.elastic_agent.elasticsearch_url
          ),
          elasticCount(
            alertQuery,
            parsed.start,
            parsed.end,
            parsed.timestamp_field,
            loaded.plan.instrumentation?.elastic_agent.elasticsearch_url
          ),
        ]);
        const execution = loaded.executions.find(
          (record) =>
            record.test_guid === test.test_guid &&
            (record.stage === "execute" || record.stage === "manual")
        );
        const behaviorConfirmed =
          execution?.status === "passed" && execution.behavior_success === true;
        const outcome: AtomicCoverageRecord["outcome"] =
          !behaviorConfirmed
            ? "not_applicable"
            : rawCount === 0
              ? "no_telemetry"
              : alertCount === 0
                ? "missed"
                : "detected";
        const evidencePath = writeCoverageEvidence(loaded.dir, {
          test_guid: test.test_guid,
          start: parsed.start,
          end: parsed.end,
          raw_event_count: rawCount,
          alert_count: alertCount,
          behavior_success: execution?.behavior_success ?? false,
          outcome,
          raw_indices: rawQuery.indices,
          alert_indices: alertQuery.indices,
        });
        const snapshot = store.recordCoverage(parsed.run_id, {
          test_guid: test.test_guid,
          outcome,
          raw_event_count: rawCount,
          alert_count: alertCount,
          detector: "elastic",
          evidence: evidencePath,
          reason:
            outcome === "not_applicable"
              ? "Telemetry counts are contextual only because digest-approved behavior success criteria did not pass"
              : outcome === "detected"
              ? "Raw telemetry and at least one matching alert were observed"
              : outcome === "missed"
                ? "Raw telemetry was observed but no matching alert was found"
                : "No matching raw telemetry was found in the bounded window",
        });
        return textResult({
          ok: true,
          test_guid: test.test_guid,
          outcome,
          raw_event_count: rawCount,
          alert_count: alertCount,
          evidence_path: evidencePath,
          run: snapshot,
        });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}

async function elasticCount(
  plan: AtomicQueryPlan,
  start: string,
  end: string,
  timestampField: string,
  approvedBase?: string
): Promise<number> {
  const base = approvedBase ?? process.env.ELASTICSEARCH_URL;
  const apiKey = getElasticEnvironment().apiKey;
  if (!base || !apiKey) {
    throw new Error(
      "The approved plan needs an Elasticsearch output URL and ELASTIC_API_KEY is required"
    );
  }
  assertAllowedIndices(plan.indices);
  const root = base.endsWith("/") ? base : `${base}/`;
  const indices = plan.indices.join(",");
  const url = new URL(`${indices}/_count`, root);
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `ApiKey ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      query: {
        bool: {
          filter: [
            plan.query,
            { range: { [timestampField]: { gte: start, lte: end } } },
          ],
        },
      },
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    const body = (await response.text()).slice(0, 2_000);
    throw new Error(`Elastic _count failed (${response.status}): ${body}`);
  }
  const body = (await response.json()) as { count?: unknown };
  if (typeof body.count !== "number") throw new Error("Elastic response has no numeric count");
  return body.count;
}

function assertAllowedIndices(indices: readonly string[]): void {
  const configured = process.env.ELASTIC_INDEX_ALLOWLIST ??
    "logs-*,filebeat-*,.alerts-security.alerts-*";
  const patterns = configured.split(",").map((value) => value.trim()).filter(Boolean);
  for (const index of indices) {
    if (!/^[A-Za-z0-9._*:-]+$/.test(index)) throw new Error(`Invalid index expression ${index}`);
    if (!patterns.some((pattern) => globMatches(pattern, index))) {
      throw new Error(`Index ${index} is outside ELASTIC_INDEX_ALLOWLIST`);
    }
  }
}

function globMatches(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(value);
}

function writeCoverageEvidence(runDir: string, value: unknown): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const file = path.join(evidenceDir, `${new Date().toISOString().replace(/[:.]/g, "-")}-coverage.json`);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return file;
}

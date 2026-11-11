/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getElasticEnvironment } from "./elastic-fleet.js";
import type {
  AtomicCoverageRecord,
  AtomicExecutionRecord,
  AtomicTestPlan,
  LoadedRun,
} from "../tools/atomic-run-state.js";

const TERMINAL_PHASES = new Set([
  "completed",
  "completed_with_findings",
  "cleanup_failed",
  "blocked",
]);

export const DEFAULT_ATOMIC_RESULTS_INDEX = "logs-atomic.results-default";

export type AtomicResultDocument = {
  readonly id: string;
  readonly test_guid: string;
  readonly document: Readonly<Record<string, unknown>>;
};

export type AtomicResultPublish = {
  readonly ok: boolean;
  readonly index: string;
  readonly outbox_path: string;
  readonly documents: readonly {
    readonly test_guid: string;
    readonly document_id: string;
    readonly status: number;
    readonly result: "created" | "updated";
  }[];
};

export function atomicResultsIndex(): string {
  const value = (process.env.ATOMIC_RESULTS_INDEX ?? DEFAULT_ATOMIC_RESULTS_INDEX).trim();
  if (!/^[a-z0-9][a-z0-9._-]{0,254}$/.test(value)) {
    throw new Error("ATOMIC_RESULTS_INDEX must be a lowercase Elasticsearch index or data-stream name");
  }
  return value;
}

export function buildAtomicResultDocuments(
  loaded: Readonly<LoadedRun>,
  campaignId?: string
): readonly AtomicResultDocument[] {
  if (!loaded.plan) throw new Error("Cannot publish a run without an approved plan");
  const plan = loaded.plan;
  if (!TERMINAL_PHASES.has(loaded.state.phase)) {
    throw new Error(`Run ${loaded.state.run_id} is not terminal (${loaded.state.phase})`);
  }
  return plan.tests.map((test) => {
    const execution = findExecution(loaded.executions, test.test_guid, ["execute", "manual"]);
    const cleanup = findExecution(loaded.executions, test.test_guid, ["cleanup"]);
    const coverage = loaded.coverage.find((record) => record.test_guid === test.test_guid);
    const unsupportedSkip =
      loaded.state.phase === "blocked" &&
      coverage?.outcome === "not_applicable" &&
      loaded.resources.every((resource) => resource.cleaned);
    const resultReason = coverage?.reason ?? loaded.state.blocked_reason ?? execution?.notes;
    const timestamp =
      execution?.ended_at ?? cleanup?.ended_at ?? loaded.state.terminal_at ?? loaded.state.created_at;
    const eventOutcome = unsupportedSkip
      ? "unknown"
      : execution?.status === "passed" && execution.behavior_success === true
        ? "success"
        : execution
          ? "failure"
          : "unknown";
    const duration = execution
      ? Math.max(0, Date.parse(execution.ended_at) - Date.parse(execution.started_at)) * 1_000_000
      : undefined;
    const documentId = createHash("sha256")
      .update(
        campaignId
          ? `${campaignId}:${test.test_guid}`
          : `standalone:${loaded.state.run_id}:${test.test_guid}`,
        "utf8"
      )
      .digest("hex");
    return {
      id: documentId,
      test_guid: test.test_guid,
      document: compact({
        "@timestamp": timestamp,
        ecs: { version: "9.0.0" },
        event: {
          kind: "event",
          category: ["configuration"],
          type: ["info"],
          action: "atomic-linux-emulation-result",
          module: "atomic",
          dataset: "atomic.results",
          outcome: eventOutcome,
          start: execution?.started_at,
          end: execution?.ended_at,
          duration,
          reason: resultReason,
        },
        observer: {
          vendor: "linux-atomic-emulation",
          product: "linux-atomic-emulation-mcp",
          type: "emulation-harness",
        },
        service: { name: "linux-atomic-emulation" },
        data_stream: { type: "logs", dataset: "atomic.results", namespace: "default" },
        host: { name: plan.scope.target_id, os: { type: plan.scope.platform } },
        user: { name: plan.scope.execution_user },
        threat: {
          technique: {
            id: [test.technique_id],
            name: [test.name],
          },
        },
        atomic: {
          schema_version: 2,
          campaign: campaignId ? { id: campaignId } : undefined,
          run: {
            id: loaded.state.run_id,
            name: loaded.state.name,
            phase: unsupportedSkip ? "skipped" : loaded.state.phase,
            original_phase: unsupportedSkip ? loaded.state.phase : undefined,
            mode: plan.mode,
            type: plan.type,
            plan_digest: loaded.state.plan_digest,
            created_at: loaded.state.created_at,
            approved_at: loaded.state.approved_at,
            terminal_at: loaded.state.terminal_at,
            blocked_reason: unsupportedSkip ? null : loaded.state.blocked_reason,
            residual_count: unsupportedSkip ? 0 : loaded.state.residual_count,
            coverage_outcome: unsupportedSkip ? "skipped" : loaded.state.coverage_outcome,
          },
          source: {
            repository: plan.source.repository,
            revision: plan.source.revision,
            catalog_digest: plan.source.catalog_digest,
            definition_digest: test.definition_digest,
            runner_repository: plan.runner.repository,
            runner_revision: plan.runner.revision,
          },
          target: {
            kind: plan.scope.target_kind,
            profile: plan.scope.target_profile,
            platform: plan.scope.platform,
            distro: plan.scope.distro,
            lifecycle: plan.scope.lifecycle,
            network: plan.scope.network,
            capabilities: plan.scope.capabilities,
            status: unsupportedSkip
              ? loaded.resources.length === 0
                ? "not_provisioned"
                : "cleaned_after_skip"
              : "provisioned_for_run",
          },
          links: resultLinks(
            plan.instrumentation?.elastic_agent.kibana_url,
            !unsupportedSkip,
            test.telemetry,
            unsupportedSkip ? resultReason : undefined
          ),
          test: resultTest(test),
          execution: unsupportedSkip
            ? {
                stage: "not_started",
                status: "skipped",
                behavior_success: false,
                exit_code: null,
                started_at: null,
                ended_at: null,
                has_evidence: false,
                notes: resultReason,
              }
            : execution
            ? {
                stage: execution.stage,
                status: execution.status,
                behavior_success: execution.behavior_success ?? false,
                exit_code: execution.exit_code,
                started_at: execution.started_at,
                ended_at: execution.ended_at,
                has_evidence: Boolean(execution.evidence_path),
                notes: execution.notes,
              }
            : { status: "not_recorded", behavior_success: false },
          coverage: unsupportedSkip
            ? {
                outcome: "skipped",
                raw_event_count: coverage?.raw_event_count ?? 0,
                alert_count: coverage?.alert_count ?? 0,
                detector: coverage?.detector ?? "elastic",
                has_evidence: Boolean(coverage?.evidence),
                reason: resultReason,
              }
            : resultCoverage(coverage),
          cleanup: unsupportedSkip
            ? { status: "not_required" }
            : cleanup
            ? {
                status: cleanup.status,
                exit_code: cleanup.exit_code,
                started_at: cleanup.started_at,
                ended_at: cleanup.ended_at,
                has_evidence: Boolean(cleanup.evidence_path),
                notes: cleanup.notes,
              }
            : { status: test.cleanup_expected ? "not_recorded" : "not_required" },
        },
      }),
    };
  });
}

export function buildAtomicSkippedResultDocuments(input: {
  readonly campaignId: string;
  readonly campaignName: string;
  readonly campaignPlanDigest: string;
  readonly campaignCreatedAt: string;
  readonly campaignApprovedAt?: string;
  readonly timestamp: string;
  readonly kibanaUrl?: string;
  readonly source: {
    readonly repository: string;
    readonly revision: string;
    readonly catalog_digest: string;
  };
  readonly tests: readonly {
    readonly technique_id: string;
    readonly test_guid: string;
    readonly name: string;
    readonly executor: string;
    readonly execution_mode: "runner" | "operator";
    readonly elevation_required: boolean;
    readonly cleanup_expected: boolean;
    readonly risk_flags: readonly string[];
    readonly definition_digest: string;
    readonly reason: string;
    readonly target_platform: "linux" | "freebsd";
    readonly preferred_distro: string;
    readonly target_profile: "server" | "desktop" | "custom";
  }[];
}): readonly AtomicResultDocument[] {
  return input.tests.map((test) => {
    const id = createHash("sha256")
      .update(`${input.campaignId}:${test.test_guid}`, "utf8")
      .digest("hex");
    return {
      id,
      test_guid: test.test_guid,
      document: compact({
        "@timestamp": input.timestamp,
        ecs: { version: "9.0.0" },
        event: {
          kind: "event",
          category: ["configuration"],
          type: ["info"],
          action: "atomic-linux-emulation-result",
          module: "atomic",
          dataset: "atomic.results",
          outcome: "unknown",
          start: input.timestamp,
          end: input.timestamp,
          duration: 0,
          reason: test.reason,
        },
        observer: {
          vendor: "linux-atomic-emulation",
          product: "linux-atomic-emulation-mcp",
          type: "emulation-harness",
        },
        service: { name: "linux-atomic-emulation" },
        data_stream: { type: "logs", dataset: "atomic.results", namespace: "default" },
        host: {
          name: "not-provisioned",
          os: { type: test.target_platform },
        },
        user: { name: "not-applicable" },
        threat: { technique: { id: [test.technique_id], name: [test.name] } },
        atomic: {
          schema_version: 2,
          campaign: { id: input.campaignId, name: input.campaignName },
          run: {
            id: `skip-${test.test_guid}`,
            name: `Skipped: ${test.name}`,
            phase: "skipped",
            mode: "coverage",
            type: "full",
            plan_digest: input.campaignPlanDigest,
            created_at: input.campaignCreatedAt,
            approved_at: input.campaignApprovedAt ?? null,
            terminal_at: input.timestamp,
            blocked_reason: null,
            residual_count: 0,
            coverage_outcome: "skipped",
          },
          source: {
            repository: input.source.repository,
            revision: input.source.revision,
            catalog_digest: input.source.catalog_digest,
            definition_digest: test.definition_digest,
            runner_repository: null,
            runner_revision: null,
          },
          target: {
            kind: "none",
            profile: test.target_profile,
            platform: test.target_platform,
            distro: test.preferred_distro,
            lifecycle: "not_provisioned",
            network: "not_applicable",
            capabilities: [],
            status: "not_provisioned",
          },
          links: resultLinks(input.kibanaUrl, false, undefined, test.reason),
          test: {
            guid: test.test_guid,
            technique_id: test.technique_id,
            name: test.name,
            executor: test.executor,
            execution_mode: test.execution_mode,
            elevation_required: test.elevation_required,
            required_capabilities: [],
            cleanup_expected: test.cleanup_expected,
            risk_flags: test.risk_flags,
            expected_outcome: `Skipped: ${test.reason}`,
          },
          execution: {
            stage: "not_started",
            status: "skipped",
            behavior_success: false,
            exit_code: null,
            started_at: null,
            ended_at: null,
            has_evidence: false,
            notes: test.reason,
            reason: test.reason,
          },
          coverage: {
            outcome: "skipped",
            raw_event_count: 0,
            alert_count: 0,
            detector: "elastic",
            has_evidence: false,
            reason: test.reason,
          },
          cleanup: { status: "not_required" },
        },
      }),
    };
  });
}

export async function publishAtomicRunResults(
  loaded: Readonly<LoadedRun>,
  options: {
    readonly campaignId?: string;
    readonly fetchImpl?: typeof fetch;
    readonly additionalDocuments?: readonly AtomicResultDocument[];
  } = {}
): Promise<AtomicResultPublish> {
  if (!loaded.plan?.instrumentation?.elastic_agent) {
    throw new Error("The approved run has no discovered Elasticsearch output");
  }
  const environment = getElasticEnvironment();
  const approvedKibana = normalizeHttpsUrl(
    loaded.plan.instrumentation.elastic_agent.kibana_url,
    "approved Kibana URL"
  );
  if (approvedKibana !== environment.kibanaUrl) {
    throw new Error("KIBANA_URL does not match the run's digest-approved Elastic stack");
  }
  const elasticsearchUrl = normalizeHttpsUrl(
    loaded.plan.instrumentation.elastic_agent.elasticsearch_url,
    "approved Elasticsearch output"
  );
  const index = atomicResultsIndex();
  const documents = [
    ...buildAtomicResultDocuments(loaded, options.campaignId),
    ...(options.additionalDocuments ?? []),
  ];
  const documentIds = new Set(documents.map((document) => document.id));
  if (documentIds.size !== documents.length) {
    throw new Error("Elastic publication contains duplicate campaign/GUID result documents");
  }
  const ndjson = documents.flatMap(({ id, document }) => [
    JSON.stringify({ index: { _index: index, _id: id } }),
    JSON.stringify(document),
  ]).join("\n") + "\n";
  const outboxPath = writeOutbox(loaded.dir, ndjson);
  const url = new URL("_bulk", `${elasticsearchUrl}/`);
  const response = await (options.fetchImpl ?? fetch)(url, {
    method: "POST",
    headers: {
      authorization: `ApiKey ${environment.apiKey}`,
      "content-type": "application/x-ndjson",
    },
    body: ndjson,
    signal: AbortSignal.timeout(60_000),
  });
  const bodyText = await response.text();
  if (!response.ok) {
    throw new Error(`Elastic result ingestion failed (${response.status}): ${bodyText.slice(0, 2_000)}`);
  }
  const body = JSON.parse(bodyText) as {
    items?: Array<{ index?: { status?: unknown; error?: unknown } }>;
  };
  if (!Array.isArray(body.items) || body.items.length !== documents.length) {
    throw new Error("Elastic _bulk response did not account for every result document");
  }
  const published = body.items.map((item, indexPosition) => {
    const status = item.index?.status;
    const source = documents[indexPosition]!;
    if (status !== 200 && status !== 201) {
      throw new Error(
        `Elastic rejected result ${source.id} (${String(status)}): ${JSON.stringify(item.index?.error).slice(0, 1_000)}`
      );
    }
    return {
      test_guid: source.test_guid,
      document_id: source.id,
      status,
      result: status === 201 ? "created" as const : "updated" as const,
    };
  });
  return { ok: true, index, outbox_path: outboxPath, documents: published };
}

function resultLinks(
  kibanaUrl: string | undefined,
  available: boolean,
  telemetry?: AtomicTestPlan["telemetry"],
  reason?: string
): Record<string, unknown> | undefined {
  if (!kibanaUrl) return undefined;
  const base = normalizeHttpsUrl(kibanaUrl, "approved Kibana URL");
  return {
    logs: compact({
      url: `${base}/app/discover`,
      available: available && Boolean(telemetry?.raw),
      indices: telemetry?.raw?.indices,
      query: telemetry?.raw?.query,
      reason: available ? undefined : reason,
    }),
    alerts: compact({
      url: `${base}/app/security/alerts`,
      available: available && Boolean(telemetry?.alerts),
      indices: telemetry?.alerts?.indices,
      query: telemetry?.alerts?.query,
      reason: available ? undefined : reason,
    }),
  };
}

function resultTest(test: AtomicTestPlan): Record<string, unknown> {
  return compact({
    guid: test.test_guid,
    technique_id: test.technique_id,
    name: test.name,
    executor: test.executor,
    execution_mode: test.execution_mode,
    elevation_required: test.elevation_required,
    required_capabilities: test.required_capabilities,
    cleanup_expected: test.cleanup_expected,
    risk_flags: test.risk_flags,
    expected_outcome: test.expected_outcome,
  });
}

function resultCoverage(coverage: AtomicCoverageRecord | undefined): Record<string, unknown> {
  return coverage
    ? compact({
        outcome: coverage.outcome,
        raw_event_count: coverage.raw_event_count,
        alert_count: coverage.alert_count,
        detector: coverage.detector,
        has_evidence: Boolean(coverage.evidence),
        reason: coverage.reason,
      })
    : { outcome: "not_recorded" };
}

function findExecution(
  executions: readonly AtomicExecutionRecord[],
  testGuid: string,
  stages: readonly AtomicExecutionRecord["stage"][]
): AtomicExecutionRecord | undefined {
  return executions.find(
    (record) => record.test_guid === testGuid && stages.includes(record.stage)
  );
}

function compact<T>(value: T): T {
  if (Array.isArray(value)) return value.map(compact) as T;
  if (!value || typeof value !== "object") return value;
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (item !== undefined) result[key] = compact(item);
  }
  return result as T;
}

function writeOutbox(runDir: string, ndjson: string): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const outbox = path.join(evidenceDir, "elastic-results.ndjson");
  fs.writeFileSync(outbox, ndjson, { encoding: "utf8", mode: 0o600 });
  return outbox;
}

function normalizeHttpsUrl(value: string, label: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error(`${label} must be credential-free HTTPS`);
  }
  return parsed.toString().replace(/\/$/, "");
}

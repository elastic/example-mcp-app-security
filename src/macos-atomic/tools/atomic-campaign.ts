/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { loadMacosCatalog, type MacosAtomicTest } from "../catalog/catalog.js";
import { publishAtomicRunResults } from "../execution/elastic-results.js";
import { sha256 } from "../shared/json.js";
import { assertSafeRunId, COMMIT_RE } from "../shared/validation.js";
import {
  createAtomicRunStore,
  type AtomicPlan,
  type LoadedRun,
  type AtomicRunStore,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

type CampaignPhase =
  | "awaiting_approval"
  | "active"
  | "completed"
  | "completed_with_findings";

type CampaignRoute =
  | "server_runner"
  | "system_runner"
  | "desktop_runner"
  | "desktop_operator"
  | "custom_runner"
  | "custom_operator"
  | "real_hardware_runner"
  | "real_hardware_operator";

type ApprovalLane = "standard" | "operator" | "high_risk" | "external_target";
type VmIsolation = "shared_vm" | "exclusive_vm";
type CampaignDisposition = "execute";
type CampaignEntryStatus =
  | "pending"
  | "running"
  | "completed"
  | "completed_with_findings"
  | "cleanup_failed"
  | "blocked";
const RESULT_DOCUMENT_SCHEMA_VERSION = 2;

type CampaignEntry = {
  readonly technique_id: string;
  readonly technique_name: string;
  readonly test_guid: string;
  readonly name: string;
  readonly executor: string;
  readonly elevation_required: boolean;
  readonly dependency_count: number;
  readonly has_cleanup: boolean;
  readonly manual: boolean;
  readonly shared_target_safe: boolean;
  readonly risk_flags: readonly string[];
  readonly definition_digest: string;
  readonly definition_file: string;
  readonly route: CampaignRoute;
  readonly disposition: CampaignDisposition;
  readonly skip_reason?: string;
  readonly approval_lane: ApprovalLane;
  readonly vm_isolation: VmIsolation;
  readonly isolation_reasons: readonly string[];
  readonly batch_key: string;
  readonly target_platform: "macos";
  readonly preferred_distro: string;
  readonly preferred_architecture: "arm64" | "x86_64" | "any";
  readonly target_profile: "server" | "desktop" | "custom";
  readonly status: CampaignEntryStatus;
  readonly run_id?: string;
  readonly run_phase?: string;
  readonly coverage_outcome?: string;
  readonly result_published?: boolean;
  readonly result_document_id?: string;
  readonly result_schema_version?: number;
};

type CampaignState = {
  readonly schema_version: 2;
  readonly campaign_id: string;
  readonly name: string;
  readonly phase: CampaignPhase;
  readonly created_at: string;
  readonly approved_at?: string;
  readonly plan_digest: string;
  readonly retry_scope?: readonly string[];
  readonly batch_approval?: BatchApproval;
  readonly source: {
    readonly atomics_path: string;
    readonly revision: string;
    readonly catalog_digest: string;
    readonly macos_test_count: number;
  };
  readonly entries: readonly CampaignEntry[];
};

type BatchApproval = {
  readonly schema_version: 1;
  readonly digest: string;
  readonly prepared_at: string;
  readonly approved_at?: string;
  readonly campaign_plan_digest: string;
  readonly test_guids: readonly string[];
  readonly runner: AtomicPlan["runner"];
  readonly instrumentation?: AtomicPlan["instrumentation"];
  readonly constraints: {
    readonly classification: "owned-disposable-lab";
    readonly max_ttl_minutes: number;
    readonly allow_digest_bound_setup_steps: true;
    readonly allow_digest_bound_fixtures: true;
    readonly allow_declared_packages: true;
    readonly allow_reboot_only_for_reboot_lane: true;
    readonly allow_destructive_only_for_high_risk_lane: true;
    readonly allow_external_only_for_external_target_lane: true;
  };
};

const campaignSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("prepare_batch_approval"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    run_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
  z.object({
    action: z.literal("approve_batch"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    batch_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  }),
  z.object({
    action: z.literal("approve_run_batch"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    run_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
  z.object({
    action: z.literal("reopen_exceptions"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    test_guids: z.array(z.string().uuid()).min(1).max(434),
  }),
  z.object({
    action: z.literal("requeue_batch_finding"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    run_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
  z.object({
    action: z.literal("refresh_routes"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
  z.object({
    action: z.literal("create"),
    name: z.string().min(1).max(200),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
    atomics_path: z.string().min(1),
  }),
  z.object({
    action: z.literal("approve"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    plan_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  }),
  z.object({
    action: z.literal("status"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
  z.object({
    action: z.literal("next"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    batch_key: z.string().min(1).max(300).optional(),
    limit: z.number().int().min(1).max(25).default(10),
  }),
  z.object({
    action: z.literal("attach_run"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    run_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
  z.object({
    action: z.literal("sync_run"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    run_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    publish_results: z.boolean().default(true),
  }),
  z.object({
    action: z.literal("list"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
    status: z.enum([
      "pending",
      "running",
      "completed",
      "completed_with_findings",
      "cleanup_failed",
      "blocked",
    ]).optional(),
    route: z.enum([
      "server_runner",
      "system_runner",
      "desktop_runner",
      "desktop_operator",
      "custom_runner",
      "custom_operator",
      "real_hardware_runner",
      "real_hardware_operator",
    ]).optional(),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(200).default(50),
  }),
  z.object({
    action: z.literal("finalize"),
    campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/),
  }),
]);

const campaignToolSchema = z.object({
  action: z.enum([
    "create",
    "approve",
    "status",
    "next",
    "attach_run",
    "sync_run",
    "list",
    "finalize",
    "refresh_routes",
    "reopen_exceptions",
    "requeue_batch_finding",
    "prepare_batch_approval",
    "approve_batch",
    "approve_run_batch",
  ]),
  name: z.string().min(1).max(200).optional(),
  campaign_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
  atomics_path: z.string().min(1).optional(),
  plan_digest: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
  batch_digest: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
  batch_key: z.string().min(1).max(300).optional(),
  run_id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,80}$/).optional(),
  publish_results: z.boolean().default(true),
  status: z.enum([
    "pending",
    "running",
    "completed",
    "completed_with_findings",
    "cleanup_failed",
    "blocked",
  ]).optional(),
  route: z.enum([
    "server_runner",
    "system_runner",
    "desktop_runner",
    "desktop_operator",
    "custom_runner",
    "custom_operator",
    "real_hardware_runner",
    "real_hardware_operator",
  ]).optional(),
  offset: z.number().int().min(0).default(0),
  limit: z.number().int().min(1).max(200).default(50),
  test_guids: z.array(z.string().uuid()).min(1).max(434).optional(),
});

export function registerAtomicCampaignTool(
  server: McpServer,
  runStore: AtomicRunStore = createAtomicRunStore(),
  campaignStore = createAtomicCampaignStore()
): void {
  server.registerTool(
    "macos-atomic-campaign",
    {
      title: "macOS Atomic Campaign",
      description:
        "Create a digest-approved, resumable queue containing every macOS-tagged Atomic test. The queue routes tests by architecture and target capability, isolates contaminating tests, supports one digest-approved policy for all exact run plans, can reopen an exact digest-bound exception set, and publishes one current result per campaign/GUID to the approved Elasticsearch output.",
      inputSchema: campaignToolSchema,
    },
    async (input) => {
      try {
        const parsed = campaignSchema.parse(input);
        if (parsed.action === "prepare_batch_approval") {
          const loaded = runStore.getLoaded(parsed.run_id);
          if (!loaded.plan) throw new Error("Batch approval needs a seed run with an exact plan");
          return textResult(
            campaignStore.prepareBatchApproval(parsed.campaign_id, loaded.plan)
          );
        }
        if (parsed.action === "approve_batch") {
          return textResult(
            campaignStore.approveBatch(parsed.campaign_id, parsed.batch_digest)
          );
        }
        if (parsed.action === "approve_run_batch") {
          let campaign = campaignStore.load(parsed.campaign_id);
          assertActive(campaign);
          const loaded = runStore.getLoaded(parsed.run_id);
          assertBatchApprovedPlan(campaign, loaded);
          campaign = attachRun(campaign, loaded);
          const approved = runStore.approve(
            parsed.run_id,
            String(loaded.state.plan_digest)
          );
          campaignStore.save(campaign);
          return textResult({
            ok: true,
            batch_digest: campaign.batch_approval?.digest,
            exact_plan_digest: loaded.state.plan_digest,
            run: approved,
            campaign: campaignSnapshot(campaign),
          });
        }
        if (parsed.action === "create") {
          return textResult(campaignStore.create(parsed));
        }
        if (parsed.action === "refresh_routes") {
          return textResult(campaignStore.refreshRoutes(parsed.campaign_id));
        }
        if (parsed.action === "reopen_exceptions") {
          return textResult(
            campaignStore.reopenExceptions(parsed.campaign_id, parsed.test_guids)
          );
        }
        if (parsed.action === "requeue_batch_finding") {
          const loaded = runStore.getLoaded(parsed.run_id);
          return textResult(
            campaignStore.requeueBatchFinding(parsed.campaign_id, loaded)
          );
        }
        if (parsed.action === "approve") {
          return textResult(campaignStore.approve(parsed.campaign_id, parsed.plan_digest));
        }
        if (parsed.action === "status") {
          return textResult(campaignStore.status(parsed.campaign_id));
        }
        if (parsed.action === "next") {
          return textResult(
            campaignStore.next(parsed.campaign_id, parsed.limit, parsed.batch_key)
          );
        }
        if (parsed.action === "attach_run") {
          const campaign = campaignStore.load(parsed.campaign_id);
          assertActive(campaign);
          const loaded = runStore.getLoaded(parsed.run_id);
          const updated = attachRun(campaign, loaded);
          campaignStore.save(updated);
          return textResult({ ok: true, ...campaignSnapshot(updated), run_id: parsed.run_id });
        }
        if (parsed.action === "sync_run") {
          let campaign = campaignStore.load(parsed.campaign_id);
          assertActive(campaign);
          const loaded = runStore.getLoaded(parsed.run_id);
          if (!loaded.plan) throw new Error("Cannot synchronize a run without a plan");
          campaign = synchronizeRun(campaign, loaded);
          campaignStore.save(campaign);
          if (!parsed.publish_results) {
            return textResult({
              ok: true,
              ...campaignSnapshot(campaign),
              run_id: parsed.run_id,
              results_published: false,
            });
          }
          const expectedPublicationGuids = loaded.plan.tests.map(
            (test) => test.test_guid
          );
          const publication = await publishAtomicRunResults(loaded, {
            campaignId: parsed.campaign_id,
          });
          campaign = markPublished(
            campaign,
            expectedPublicationGuids,
            publication.documents
          );
          campaignStore.save(campaign);
          return textResult({
            ok: true,
            ...campaignSnapshot(campaign),
            run_id: parsed.run_id,
            publication,
          });
        }
        if (parsed.action === "list") {
          return textResult(
            campaignStore.list(
              parsed.campaign_id,
              parsed.offset,
              parsed.limit,
              parsed.status,
              parsed.route
            )
          );
        }
        return textResult(campaignStore.finalize(parsed.campaign_id));
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}

export function createAtomicCampaignStore(
  options: { readonly baseDir?: string } = {}
) {
  const runRoot = path.resolve(
    process.env.MACOS_ATOMIC_RUNS_DIR ?? path.join(process.cwd(), "macos-atomic-runs")
  );
  const baseDir = path.resolve(
    options.baseDir ?? process.env.MACOS_ATOMIC_CAMPAIGNS_DIR ?? path.join(runRoot, "_campaigns")
  );

  function fileFor(campaignId: string): string {
    assertSafeRunId(campaignId);
    const file = path.resolve(baseDir, `${campaignId}.json`);
    const relative = path.relative(baseDir, file);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error("campaign_id resolves outside the campaign directory");
    }
    return file;
  }

  function load(campaignId: string): CampaignState {
    const file = fileFor(campaignId);
    if (!fs.existsSync(file)) throw new Error(`Campaign ${campaignId} does not exist`);
    const state = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<CampaignState>;
    if (state.schema_version !== 2) {
      throw new Error(
        `Campaign ${campaignId} uses schema ${String(state.schema_version)}; create a fresh campaign so VM-isolation decisions are digest-bound`
      );
    }
    return state as CampaignState;
  }

  function save(state: CampaignState): void {
    const file = fileFor(state.campaign_id);
    fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
    const temporary = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    fs.renameSync(temporary, file);
  }

  return {
    load,
    save,
    create(input: { readonly name: string; readonly campaign_id?: string; readonly atomics_path: string }) {
      const catalog = loadMacosCatalog(input.atomics_path);
      if (!catalog.revision || !COMMIT_RE.test(catalog.revision)) {
        throw new Error("Campaign source must be an immutable Git revision");
      }
      if (catalog.skipped_files.length) {
        throw new Error(
          `Catalog has ${catalog.skipped_files.length} skipped files; resolve them before claiming full coverage`
        );
      }
      const slug = input.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "").slice(0, 40) || "macos-atomic-campaign";
      const campaignId = input.campaign_id ?? `${slug}-${randomBytes(3).toString("hex")}`;
      if (fs.existsSync(fileFor(campaignId))) throw new Error(`Campaign ${campaignId} already exists`);
      const entries = catalog.tests.map(campaignEntry);
      const digest = campaignDigest({
        campaign_id: campaignId,
        name: input.name,
        source: {
          atomics_path: catalog.atomics_path,
          revision: catalog.revision,
          catalog_digest: catalog.catalog_digest,
          macos_test_count: catalog.tests.length,
        },
        entries,
        retry_scope: [],
      });
      const state: CampaignState = {
        schema_version: 2,
        campaign_id: campaignId,
        name: input.name,
        phase: "awaiting_approval",
        created_at: new Date().toISOString(),
        plan_digest: digest,
        retry_scope: [],
        source: {
          atomics_path: catalog.atomics_path,
          revision: catalog.revision,
          catalog_digest: catalog.catalog_digest,
          macos_test_count: catalog.tests.length,
        },
        entries,
      };
      save(state);
      return {
        ok: true,
        ...campaignSnapshot(state),
        stop: true,
        stop_reason:
          "Present the complete catalog count, route/risk breakdown, and campaign digest for explicit approval.",
      };
    },
    approve(campaignId: string, digest: string) {
      const state = load(campaignId);
      if (state.phase !== "awaiting_approval") {
        throw new Error(`Campaign phase is ${state.phase}; expected awaiting_approval`);
      }
      if (state.plan_digest !== digest) throw new Error("Campaign plan_digest does not match");
      const updated: CampaignState = {
        ...state,
        phase: "active",
        approved_at: new Date().toISOString(),
      };
      save(updated);
      return { ok: true, ...campaignSnapshot(updated) };
    },
    prepareBatchApproval(campaignId: string, seedPlan: AtomicPlan) {
      const state = load(campaignId);
      assertActive(state);
      if (state.entries.some((entry) => entry.status === "running")) {
        throw new Error("Finish and clean the running test before preparing batch approval");
      }
      if (
        seedPlan.source.revision !== state.source.revision ||
        seedPlan.source.catalog_digest !== state.source.catalog_digest
      ) {
        throw new Error("Batch seed plan differs from the approved campaign source");
      }
      if (!seedPlan.instrumentation?.elastic_agent) {
        throw new Error("Batch approval requires the exact discovered Elastic instrumentation");
      }
      const testGuids = state.entries
        .filter((entry) => entry.status === "pending")
        .map((entry) => entry.test_guid)
        .sort();
      if (!testGuids.length) throw new Error("Campaign has no pending tests to batch-approve");
      const payload = {
        schema_version: 1 as const,
        campaign_id: state.campaign_id,
        campaign_plan_digest: state.plan_digest,
        source: state.source,
        test_guids: testGuids,
        runner: seedPlan.runner,
        instrumentation: seedPlan.instrumentation,
        constraints: {
          classification: "owned-disposable-lab" as const,
          max_ttl_minutes: 240,
          allow_digest_bound_setup_steps: true as const,
          allow_digest_bound_fixtures: true as const,
          allow_declared_packages: true as const,
          allow_reboot_only_for_reboot_lane: true as const,
          allow_destructive_only_for_high_risk_lane: true as const,
          allow_external_only_for_external_target_lane: true as const,
        },
      };
      const digest = sha256(payload);
      const batchApproval: BatchApproval = {
        schema_version: 1,
        digest,
        prepared_at: new Date().toISOString(),
        campaign_plan_digest: state.plan_digest,
        test_guids: testGuids,
        runner: seedPlan.runner,
        instrumentation: seedPlan.instrumentation,
        constraints: payload.constraints,
      };
      const updated: CampaignState = { ...state, batch_approval: batchApproval };
      save(updated);
      return {
        ok: true,
        ...campaignSnapshot(updated),
        batch_approval: batchApprovalSummary(batchApproval, state.entries),
        stop: true,
        stop_reason:
          "Present the complete remaining scope, policy constraints, and batch digest for one explicit approval.",
      };
    },
    approveBatch(campaignId: string, digest: string) {
      const state = load(campaignId);
      assertActive(state);
      const batch = state.batch_approval;
      if (!batch) throw new Error("Prepare the batch approval before approving it");
      if (batch.digest !== digest) throw new Error("batch_digest does not match");
      const currentPending = state.entries
        .filter((entry) => entry.status === "pending")
        .map((entry) => entry.test_guid)
        .sort();
      if (JSON.stringify(currentPending) !== JSON.stringify([...batch.test_guids].sort())) {
        throw new Error("Pending campaign membership changed; prepare a fresh batch digest");
      }
      const approved: BatchApproval = {
        ...batch,
        approved_at: new Date().toISOString(),
      };
      const updated: CampaignState = { ...state, batch_approval: approved };
      save(updated);
      return {
        ok: true,
        ...campaignSnapshot(updated),
        batch_approval: batchApprovalSummary(approved, state.entries),
      };
    },
    status(campaignId: string) {
      return { ok: true, ...campaignSnapshot(load(campaignId)) };
    },
    refreshRoutes(campaignId: string) {
      const state = load(campaignId);
      if (state.entries.some((entry) => entry.status === "running")) {
        throw new Error("Finish or clean the currently running test before refreshing routes");
      }
      const catalog = loadMacosCatalog(state.source.atomics_path);
      if (
        catalog.revision !== state.source.revision ||
        catalog.catalog_digest !== state.source.catalog_digest ||
        catalog.tests.length !== state.source.macos_test_count
      ) {
        throw new Error("Pinned campaign source changed; route refresh refuses source drift");
      }
      const previous = new Map(state.entries.map((entry) => [entry.test_guid, entry]));
      const entries = catalog.tests.map((test) => {
        const routed = campaignEntry(test);
        const old = previous.get(test.test_guid);
        if (!old) throw new Error(`Campaign entry ${test.test_guid} is missing`);
        const compatibilityFailure =
          old.status === "blocked" ||
          (old.status === "completed_with_findings" && old.coverage_outcome === "not_applicable");
        if (compatibilityFailure) return routed;
        return {
          ...routed,
          status: old.status,
          run_id: old.run_id,
          run_phase: old.run_phase,
          coverage_outcome: old.coverage_outcome,
          result_published: old.result_published,
          result_document_id: old.result_document_id,
          result_schema_version: old.result_schema_version,
        };
      });
      if (entries.length !== state.entries.length) {
        throw new Error("Route refresh changed the approved campaign membership");
      }
      const planDigest = campaignDigest({
        campaign_id: state.campaign_id,
        name: state.name,
        source: state.source,
        entries,
        retry_scope: state.retry_scope ?? [],
      });
      const updated: CampaignState = {
        ...state,
        phase: "awaiting_approval",
        approved_at: undefined,
        plan_digest: planDigest,
        entries,
      };
      save(updated);
      return {
        ok: true,
        ...campaignSnapshot(updated),
        stop: true,
        stop_reason:
          "Compatibility routes changed. Approve the new campaign digest before resuming; prior blocked/not_applicable compatibility outcomes were requeued.",
      };
    },
    reopenExceptions(campaignId: string, testGuids: readonly string[]) {
      const state = load(campaignId);
      if (state.entries.some((entry) => entry.status === "running")) {
        throw new Error("Finish or clean the currently running test before reopening exceptions");
      }
      const samePendingScope =
        state.phase === "awaiting_approval" &&
        JSON.stringify([...(state.retry_scope ?? [])].sort()) === JSON.stringify([...testGuids].sort());
      if (
        !samePendingScope &&
        !new Set<CampaignPhase>(["completed", "completed_with_findings"]).has(state.phase)
      ) {
        throw new Error(
          `Campaign phase is ${state.phase}; reopen_exceptions requires a terminal campaign or the same awaiting-approval retry scope`
        );
      }
      const requested = [...new Set(testGuids)].sort();
      if (requested.length !== testGuids.length) {
        throw new Error("reopen_exceptions refuses duplicate test GUIDs");
      }
      const requestedSet = new Set(requested);
      const existing = new Map(state.entries.map((entry) => [entry.test_guid, entry]));
      const missing = requested.filter((guid) => !existing.has(guid));
      if (missing.length) {
        throw new Error(`Campaign does not contain requested GUIDs: ${missing.join(", ")}`);
      }
      const catalog = loadMacosCatalog(state.source.atomics_path);
      if (
        catalog.revision !== state.source.revision ||
        catalog.catalog_digest !== state.source.catalog_digest ||
        catalog.tests.length !== state.source.macos_test_count
      ) {
        throw new Error("Pinned campaign source changed; exception reopen refuses source drift");
      }
      const routed = new Map(catalog.tests.map((test) => [test.test_guid, campaignEntry(test)]));
      const entries = state.entries.map((entry) => {
        if (!requestedSet.has(entry.test_guid)) return entry;
        const replacement = routed.get(entry.test_guid);
        if (!replacement) throw new Error(`Catalog entry ${entry.test_guid} is missing`);
        return replacement;
      });
      const planDigest = campaignDigest({
        campaign_id: state.campaign_id,
        name: state.name,
        source: state.source,
        entries,
        retry_scope: requested,
      });
      const updated: CampaignState = {
        ...state,
        phase: "awaiting_approval",
        approved_at: undefined,
        plan_digest: planDigest,
        retry_scope: requested,
        entries,
      };
      save(updated);
      return {
        ok: true,
        ...campaignSnapshot(updated),
        retry_scope: requested,
        stop: true,
        stop_reason:
          "Present the exact retry scope, compatibility-route breakdown, and new campaign digest for explicit approval.",
      };
    },
    requeueBatchFinding(campaignId: string, loaded: LoadedRun) {
      const state = load(campaignId);
      assertActive(state);
      const batch = state.batch_approval;
      if (!batch?.approved_at) {
        throw new Error("Active finding requeue requires an approved batch policy");
      }
      if (!loaded.plan) throw new Error("Cannot requeue a run without an exact plan");
      const isPublishedNotApplicable =
        loaded.state.phase === "completed_with_findings" &&
        loaded.state.coverage_outcome === "not_applicable";
      const isCleanPreExecutionBlock =
        loaded.state.phase === "blocked" &&
        loaded.state.coverage_outcome === "pending" &&
        loaded.executions.length === 0 &&
        loaded.coverage.length === 0;
      const isCleanCompatibilityBlock =
        loaded.state.phase === "blocked" &&
        loaded.state.coverage_outcome === "not_applicable" &&
        loaded.coverage.length > 0 &&
        loaded.coverage.every((coverage) => coverage.outcome === "not_applicable") &&
        loaded.executions.every(
          (execution) =>
            !["execute", "manual"].includes(execution.stage) ||
            (execution.status !== "passed" && execution.behavior_success !== true)
        );
      if (
        !isPublishedNotApplicable &&
        !isCleanPreExecutionBlock &&
        !isCleanCompatibilityBlock
      ) {
        throw new Error(
          "Only a published not_applicable finding or a clean blocked compatibility attempt can be requeued"
        );
      }
      if (
        (isPublishedNotApplicable && loaded.state.residual_count !== 0) ||
        loaded.resources.some((resource) => !resource.cleaned)
      ) {
        throw new Error("Finish cleanup with zero residuals before requeueing the finding");
      }
      if (
        loaded.plan.source.revision !== state.source.revision ||
        loaded.plan.source.catalog_digest !== state.source.catalog_digest
      ) {
        throw new Error("Requeue refuses run source drift");
      }
      const testGuids = loaded.plan.tests.map((test) => test.test_guid);
      const batchScope = new Set(batch.test_guids);
      if (testGuids.some((guid) => !batchScope.has(guid))) {
        throw new Error("Run contains a test outside the approved batch scope");
      }
      const testGuidSet = new Set(testGuids);
      const entries = state.entries.filter((entry) => testGuidSet.has(entry.test_guid));
      const entriesMatch =
        entries.length === testGuids.length &&
        entries.every((entry) => {
          if (entry.run_id !== loaded.state.run_id) return false;
          if (isCleanPreExecutionBlock || isCleanCompatibilityBlock) {
            return (
              ["running", "blocked"].includes(entry.status) &&
              entry.result_published !== true
            );
          }
          return (
            entry.status === "completed_with_findings" &&
            entry.coverage_outcome === "not_applicable" &&
            entry.result_published === true
          );
        });
      if (!entriesMatch) {
        throw new Error(
          isCleanPreExecutionBlock
            ? "Requeue requires the clean blocked run to remain attached and unpublished"
            : "Requeue requires the terminal not_applicable result to be synchronized and published first"
        );
      }
      const updated: CampaignState = {
        ...state,
        entries: state.entries.map((entry) => {
          if (!testGuidSet.has(entry.test_guid)) return entry;
          const {
            run_id: _runId,
            run_phase: _runPhase,
            coverage_outcome: _coverageOutcome,
            result_published: _resultPublished,
            result_document_id: _resultDocumentId,
            result_schema_version: _resultSchemaVersion,
            ...staticEntry
          } = entry;
          return { ...staticEntry, status: "pending" };
        }),
      };
      save(updated);
      return {
        ok: true,
        ...campaignSnapshot(updated),
        requeued_run_id: loaded.state.run_id,
        requeued_test_guids: testGuids,
      };
    },
    next(campaignId: string, limit: number, requestedBatchKey?: string) {
      const state = load(campaignId);
      assertActive(state);
      if (
        state.entries.some(
          (entry) =>
            !entry.target_platform ||
            !entry.preferred_distro ||
            !entry.target_profile ||
            !entry.disposition
        )
      ) {
        throw new Error(
          "Campaign uses legacy compatibility or skip routes; finish any running test, then call refresh_routes and approve its new digest"
        );
      }
      const pending = state.entries.filter((entry) => entry.status === "pending");
      const first = requestedBatchKey
        ? pending.find((entry) => entry.batch_key === requestedBatchKey)
        : pending[0];
      if (!first) return { ok: true, ...campaignSnapshot(state), tests: [] };
      const batchLimit =
        first.vm_isolation === "shared_vm" &&
        first.approval_lane === "standard" &&
        !first.manual
          ? limit
          : 1;
      const tests = pending
        .filter((entry) => entry.batch_key === first.batch_key)
        .slice(0, batchLimit);
      return {
        ok: true,
        ...campaignSnapshot(state),
        batch_key: first.batch_key,
        route: first.route,
        target_platform: first.target_platform,
        preferred_distro: first.preferred_distro,
        preferred_architecture: first.preferred_architecture,
        target_kind:
          first.route.startsWith("custom_") ||
          first.route.startsWith("real_hardware_") ||
          first.preferred_architecture === "x86_64"
            ? "ssh"
            : "tart",
        target_profile: first.target_profile,
        approval_lane: first.approval_lane,
        vm_isolation: first.vm_isolation,
        isolation_reasons: first.isolation_reasons,
        tests,
      };
    },
    list(
      campaignId: string,
      offset: number,
      limit: number,
      status?: CampaignEntryStatus,
      route?: CampaignRoute
    ) {
      const state = load(campaignId);
      const filtered = state.entries.filter(
        (entry) => (!status || entry.status === status) && (!route || entry.route === route)
      );
      return {
        ok: true,
        campaign_id: campaignId,
        total: filtered.length,
        offset,
        entries: filtered.slice(offset, offset + limit),
      };
    },
    finalize(campaignId: string) {
      const state = load(campaignId);
      assertActive(state);
      const unfinished = state.entries.filter(
        (entry) =>
          entry.status === "pending" ||
          entry.status === "running" ||
          entry.status === "blocked"
      );
      if (unfinished.length) {
        throw new Error(
          `${unfinished.length} campaign tests still require execution or compatibility rerouting`
        );
      }
      const unpublished = state.entries.filter((entry) => entry.result_published !== true);
      if (unpublished.length) {
        throw new Error(`${unpublished.length} terminal test results are not published to Elastic`);
      }
      const findings = state.entries.some(
        (entry) => entry.status !== "completed" || entry.coverage_outcome !== "verified"
      );
      const updated: CampaignState = {
        ...state,
        phase: findings ? "completed_with_findings" : "completed",
      };
      save(updated);
      return { ok: true, ...campaignSnapshot(updated) };
    },
  };
}

function campaignEntry(test: MacosAtomicTest): CampaignEntry {
  const route = routeTest(test);
  const lane = approvalLane(test);
  const privilege = test.elevation_required ? "root" : "user";
  const isolationReasons = vmIsolationReasons(test, lane);
  const vmIsolation: VmIsolation = isolationReasons.length ? "exclusive_vm" : "shared_vm";
  const compatibilityKey = `${route}:${test.target_platform}:${test.preferred_distro}:${test.preferred_architecture}:${lane}:${test.executor}:${privilege}`;
  return {
    technique_id: test.technique_id,
    technique_name: test.technique_name,
    test_guid: test.test_guid,
    name: test.name,
    executor: test.executor,
    elevation_required: test.elevation_required,
    dependency_count: test.dependency_count,
    has_cleanup: test.has_cleanup,
    manual: test.manual,
    shared_target_safe: test.shared_target_safe,
    risk_flags: test.risk_flags,
    definition_digest: test.definition_digest,
    definition_file: test.definition_file,
    route,
    disposition: "execute",
    approval_lane: lane,
    vm_isolation: vmIsolation,
    isolation_reasons: isolationReasons,
    batch_key:
      vmIsolation === "exclusive_vm"
        ? `${compatibilityKey}:exclusive:${test.test_guid}`
        : `${compatibilityKey}:shared`,
    target_platform: test.target_platform,
    preferred_distro: test.preferred_distro,
    preferred_architecture: test.preferred_architecture,
    target_profile:
      route.startsWith("custom_") || route.startsWith("real_hardware_")
        ? "custom"
        : test.risk_flags.includes("gui")
          ? "desktop"
          : test.risk_flags.includes("special_runtime")
            ? "custom"
            : "server",
    status: "pending",
  };
}

function vmIsolationReasons(test: MacosAtomicTest, lane: ApprovalLane): string[] {
  const reasons = new Set<string>();
  if (lane !== "standard") reasons.add(`approval_lane:${lane}`);
  if (test.manual) reasons.add("manual_operator");
  if (test.elevation_required) reasons.add("elevated_execution");
  if (test.dependency_count > 0) reasons.add("declared_dependencies");
  if (test.has_cleanup) reasons.add("cleanup_deferred_until_run_end");
  if (!test.shared_target_safe) reasons.add("unproven_shared_target_safety");
  for (const flag of [
    "destructive",
    "external_target",
    "gui",
    "kernel",
    "network",
    "persistence",
    "real_hardware",
    "reboot",
    "sip",
    "special_runtime",
    "state_change",
    "tcc",
  ]) {
    if (test.risk_flags.includes(flag)) reasons.add(`risk:${flag}`);
  }
  return [...reasons].sort();
}

function routeTest(test: MacosAtomicTest): CampaignRoute {
  if (test.risk_flags.includes("real_hardware")) {
    return test.manual ? "real_hardware_operator" : "real_hardware_runner";
  }
  const special = test.risk_flags.includes("special_runtime");
  const privilegedPolicyChange =
    test.risk_flags.includes("sip") || test.risk_flags.includes("tcc");
  if (test.manual) {
    return special || privilegedPolicyChange ? "custom_operator" : "desktop_operator";
  }
  if (privilegedPolicyChange) return "custom_runner";
  if (special) return "custom_runner";
  if (test.risk_flags.includes("gui")) return "desktop_runner";
  if (test.risk_flags.includes("kernel") || test.risk_flags.includes("reboot")) {
    return "system_runner";
  }
  return "server_runner";
}

function approvalLane(test: MacosAtomicTest): ApprovalLane {
  if (test.risk_flags.includes("external_target")) return "external_target";
  if (test.risk_flags.includes("destructive") || test.risk_flags.includes("reboot")) {
    return "high_risk";
  }
  if (test.manual) return "operator";
  return "standard";
}

function campaignDigest(value: {
  readonly campaign_id: string;
  readonly name: string;
  readonly source: CampaignState["source"];
  readonly entries: readonly CampaignEntry[];
  readonly retry_scope?: readonly string[];
}): string {
  return sha256({
    ...value,
    entries: value.entries.map(staticCampaignEntry),
  });
}

function batchApprovalSummary(
  batch: BatchApproval,
  entries: readonly CampaignEntry[]
): Record<string, unknown> {
  const scope = new Set(batch.test_guids);
  const selected = entries.filter((entry) => scope.has(entry.test_guid));
  return {
    digest: batch.digest,
    status: batch.approved_at ? "approved" : "awaiting_approval",
    prepared_at: batch.prepared_at,
    approved_at: batch.approved_at,
    test_count: batch.test_guids.length,
    by_route: counts(selected.map((entry) => entry.route)),
    by_approval_lane: counts(selected.map((entry) => entry.approval_lane)),
    runner: batch.runner,
    instrumentation: batch.instrumentation,
    constraints: batch.constraints,
  };
}

function assertBatchApprovedPlan(
  campaign: CampaignState,
  loaded: ReturnType<AtomicRunStore["getLoaded"]>
): void {
  const batch = campaign.batch_approval;
  if (!batch?.approved_at) throw new Error("Campaign batch approval is not approved");
  if (batch.campaign_plan_digest !== campaign.plan_digest) {
    throw new Error("Campaign digest changed after batch approval");
  }
  if (!loaded.plan || loaded.state.phase !== "awaiting_approval") {
    throw new Error("Batch approval requires an exact run plan awaiting approval");
  }
  if (!loaded.state.plan_digest) throw new Error("Run has no exact plan digest");
  const plan = loaded.plan;
  if (
    plan.source.repository !== "https://github.com/redcanaryco/atomic-red-team.git" ||
    plan.source.revision !== campaign.source.revision ||
    plan.source.catalog_digest !== campaign.source.catalog_digest
  ) {
    throw new Error("Run source is outside the batch-approved campaign source");
  }
  if (sha256(plan.runner) !== sha256(batch.runner)) {
    throw new Error("Run runner revision differs from the batch approval");
  }
  if (sha256(plan.instrumentation ?? null) !== sha256(batch.instrumentation ?? null)) {
    throw new Error("Run instrumentation differs from the batch approval");
  }
  if (
    plan.scope.classification !== batch.constraints.classification ||
    plan.controls.ttl_minutes > batch.constraints.max_ttl_minutes
  ) {
    throw new Error("Run target classification or TTL exceeds the batch approval");
  }
  const approvedGuids = new Set(batch.test_guids);
  const entries = plan.tests.map((test) => {
    if (!approvedGuids.has(test.test_guid)) {
      throw new Error(`Run test ${test.test_guid} is outside the batch-approved scope`);
    }
    const entry = campaign.entries.find((candidate) => candidate.test_guid === test.test_guid);
    if (!entry) throw new Error(`Campaign entry ${test.test_guid} is missing`);
    return entry;
  });
  if (
    plan.controls.allow_reboot &&
    entries.some((entry) => !entry.risk_flags.includes("reboot"))
  ) {
    throw new Error("Run requests reboot outside a reboot campaign lane");
  }
  if (
    plan.controls.allow_destructive &&
    entries.some(
      (entry) =>
        entry.approval_lane !== "high_risk" &&
        !entry.risk_flags.includes("destructive")
    )
  ) {
    throw new Error(
      "Run requests destructive authority for a campaign entry without an approved destructive risk flag"
    );
  }
  if (
    plan.controls.allow_external_targets &&
    entries.some((entry) => entry.approval_lane !== "external_target")
  ) {
    throw new Error("Run requests external-target authority outside an external-target lane");
  }
  if ((plan.setup_steps?.length ?? 0) > 0 && plan.controls.allow_setup_commands !== true) {
    throw new Error("Digest-bound setup steps require allow_setup_commands");
  }
}

function attachRun(campaign: CampaignState, loaded: ReturnType<AtomicRunStore["getLoaded"]>): CampaignState {
  if (!loaded.plan) throw new Error("Attach the run only after its exact plan is stored");
  if (
    loaded.plan.source.revision !== campaign.source.revision ||
    loaded.plan.source.catalog_digest !== campaign.source.catalog_digest
  ) {
    throw new Error("Run source revision or catalog digest differs from the approved campaign");
  }
  const entries = loaded.plan.tests.map((test) => {
    const entry = campaign.entries.find((candidate) => candidate.test_guid === test.test_guid);
    if (!entry) throw new Error(`Run test ${test.test_guid} is not in the campaign`);
    if (entry.definition_digest !== test.definition_digest) {
      throw new Error(`Run test ${test.test_guid} definition digest differs from the campaign`);
    }
    if (entry.status !== "pending" && entry.run_id !== loaded.state.run_id) {
      throw new Error(`Campaign test ${test.test_guid} is already assigned to ${entry.run_id}`);
    }
    return entry;
  });
  const reusableTerminalResult = canReuseTerminalCampaignResult(loaded);
  const batchKeys = new Set(entries.map((entry) => entry.batch_key));
  if (batchKeys.size !== 1) throw new Error("A campaign run may contain only one compatibility batch");
  if (entries.some((entry) => entry.vm_isolation === "exclusive_vm") && entries.length !== 1) {
    throw new Error("Contamination-sensitive campaign runs must contain exactly one test");
  }
  if (
    entries.some(
      (entry) =>
        loaded.plan!.scope.platform !== entry.target_platform ||
        (!reusableTerminalResult &&
          (loaded.plan!.scope.distro.toLowerCase() !== entry.preferred_distro ||
            loaded.plan!.scope.target_profile !== entry.target_profile ||
            (entry.preferred_architecture !== "any" &&
              loaded.plan!.scope.architecture !== entry.preferred_architecture)))
    )
  ) {
    throw new Error("Run target platform/distro/profile differs from the compatibility route");
  }
  const requiresSsh = entries.some(
    (entry) =>
      entry.route.startsWith("custom_") ||
      entry.route.startsWith("real_hardware_") ||
      entry.preferred_architecture === "x86_64"
  );
  if (!reusableTerminalResult && requiresSsh && loaded.plan.scope.target_kind !== "ssh") {
    throw new Error("Custom, real-hardware, and Intel macOS routes require an approved SSH target");
  }
  if (!reusableTerminalResult && !requiresSsh && loaded.plan.scope.target_kind !== "tart") {
    throw new Error("Standard Apple Silicon macOS routes require a Tart target");
  }
  if (
    entries.some(
      (entry) =>
        entry.vm_isolation === "exclusive_vm" &&
        entry.approval_lane !== "external_target" &&
        !entry.route.startsWith("custom_") &&
        !entry.route.startsWith("real_hardware_") &&
        entry.preferred_architecture !== "x86_64"
    ) &&
    !reusableTerminalResult &&
    (loaded.plan.scope.target_kind !== "tart" ||
      loaded.plan.scope.lifecycle !== "ephemeral")
  ) {
    throw new Error(
      "Exclusive non-external standard/system/desktop campaign tests require a fresh ephemeral Tart target"
    );
  }
  if (entries.some((entry) => entry.approval_lane !== "standard") && entries.length !== 1) {
    throw new Error("Operator and high-risk campaign runs must contain exactly one test");
  }
  return {
    ...campaign,
    entries: campaign.entries.map((entry) =>
      entries.some((candidate) => candidate.test_guid === entry.test_guid)
        ? { ...entry, status: "running", run_id: loaded.state.run_id }
        : entry
    ),
  };
}

export function canReuseTerminalCampaignResult(loaded: LoadedRun): boolean {
  if (!new Set(["completed", "completed_with_findings"]).has(loaded.state.phase)) return false;
  if (loaded.state.residual_count !== 0) return false;
  if (loaded.resources.some((resource) => resource.cleaned !== true)) return false;
  if (!loaded.plan) return false;
  return loaded.plan.tests.every(
    (test) =>
      loaded.executions.some(
        (execution) =>
          execution.test_guid === test.test_guid &&
          execution.stage === "execute" &&
          execution.status === "passed" &&
          execution.behavior_success === true
      ) &&
      loaded.coverage.some(
        (coverage) =>
          coverage.test_guid === test.test_guid &&
          (coverage.outcome === "detected" || coverage.outcome === "missed")
      )
  );
}

function staticCampaignEntry(entry: CampaignEntry): Record<string, unknown> {
  const {
    status: _status,
    run_id: _runId,
    run_phase: _runPhase,
    coverage_outcome: _coverageOutcome,
    result_published: _resultPublished,
    result_document_id: _resultDocumentId,
    result_schema_version: _resultSchemaVersion,
    ...staticEntry
  } = entry;
  return staticEntry;
}

function synchronizeRun(
  campaign: CampaignState,
  loaded: ReturnType<AtomicRunStore["getLoaded"]>
): CampaignState {
  if (!loaded.plan) throw new Error("Cannot synchronize a run without a plan");
  if (!new Set(["completed", "completed_with_findings", "cleanup_failed", "blocked"]).has(loaded.state.phase)) {
    throw new Error(`Run ${loaded.state.run_id} is not terminal (${loaded.state.phase})`);
  }
  const attached = campaign.entries.filter((entry) => entry.run_id === loaded.state.run_id);
  const planned = new Set(loaded.plan.tests.map((test) => test.test_guid));
  if (!attached.length || attached.some((entry) => !planned.has(entry.test_guid))) {
    throw new Error(`Run ${loaded.state.run_id} is not correctly attached to this campaign`);
  }
  return {
    ...campaign,
    entries: campaign.entries.map((entry) =>
      entry.run_id === loaded.state.run_id
        ? {
            ...entry,
            status: loaded.state.phase as CampaignEntryStatus,
            run_phase: loaded.state.phase,
            coverage_outcome: loaded.state.coverage_outcome,
            result_published: false,
            result_document_id: undefined,
          }
        : entry
    ),
  };
}

function markPublished(
  campaign: CampaignState,
  expectedGuids: readonly string[],
  documents: readonly { readonly test_guid: string; readonly document_id: string }[]
): CampaignState {
  const byGuid = new Map(documents.map((document) => [document.test_guid, document.document_id]));
  if (expectedGuids.some((testGuid) => !byGuid.has(testGuid))) {
    throw new Error("Elastic publication did not account for every campaign test in the run");
  }
  return {
    ...campaign,
    entries: campaign.entries.map((entry) => {
      const documentId = byGuid.get(entry.test_guid);
      return documentId
        ? {
            ...entry,
            result_published: true,
            result_document_id: documentId,
            result_schema_version: RESULT_DOCUMENT_SCHEMA_VERSION,
          }
        : entry;
    }),
  };
}

function assertActive(state: CampaignState): void {
  if (state.phase !== "active") {
    throw new Error(`Campaign phase is ${state.phase}; expected active`);
  }
}

function campaignSnapshot(state: CampaignState): Record<string, unknown> {
  const byStatus = counts(state.entries.map((entry) => entry.status));
  const byRoute = counts(state.entries.map((entry) => entry.route));
  const byApprovalLane = counts(state.entries.map((entry) => entry.approval_lane));
  const byVmIsolation = counts(state.entries.map((entry) => entry.vm_isolation));
  const byDisposition = counts(state.entries.map((entry) => entry.disposition));
  return {
    campaign_id: state.campaign_id,
    name: state.name,
    phase: state.phase,
    plan_digest: state.plan_digest,
    retry_count: state.retry_scope?.length ?? 0,
    source: state.source,
    total: state.entries.length,
    published: state.entries.filter((entry) => entry.result_published).length,
    by_status: byStatus,
    by_route: byRoute,
    by_disposition: byDisposition,
    by_approval_lane: byApprovalLane,
    by_vm_isolation: byVmIsolation,
    batch_approval: state.batch_approval
      ? batchApprovalSummary(state.batch_approval, state.entries)
      : undefined,
  };
}

function counts(values: readonly string[]): Record<string, number> {
  const result: Record<string, number> = {};
  for (const value of values) result[value] = (result[value] ?? 0) + 1;
  return result;
}

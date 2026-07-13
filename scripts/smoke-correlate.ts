/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Live smoke test for the workflow-driven correlation path:
 *   correlate (trigger ti-correlation workflow) → poll get_correlation_run →
 *   transform workflow findings into the render_correlation shape.
 *
 * Exercises the REAL Kibana/ES HTTP seam (auth headers, workflow run route,
 * ti-correlations doc retrieval) plus the title→fingerprint findings transform.
 *
 * Creds come from env (no secrets in-repo):
 *   ES_URL, KBN_URL, API_KEY   (KBN_API_KEY/ES_API_KEY also accepted)
 * Optional:
 *   REPORT_ID   — correlate this report (else auto-pick a diamond_suitable one)
 *   DEPTH       — free | cheap | med | full   (default full)
 *   TI_REPORTS_INDEX_PATTERN (default ti-reports*)
 *
 * Run:  npx tsx scripts/smoke-correlate.ts
 */

import { createEsClient } from "../src/elastic/es-client/index.js";
import { createKibanaClient } from "../src/elastic/kibana-client/index.js";
import { CorrelationService } from "../src/elastic/service/correlationService.js";
import { workflowFindingsToRenderShape } from "../src/tools/correlation.js";

const API_KEY = process.env.API_KEY || process.env.KBN_API_KEY || process.env.ES_API_KEY || "";
const ES_URL = process.env.ES_URL || "";
const KBN_URL = process.env.KBN_URL || "";
const DEPTH = (process.env.DEPTH || "full") as "free" | "cheap" | "med" | "full";
const INDEX = process.env.TI_REPORTS_INDEX_PATTERN?.trim() || "ti-reports*";

const POLL_INTERVAL_MS = 8_000;
const POLL_TIMEOUT_MS = 8 * 60_000;

function die(msg: string): never {
  console.error(`\n[smoke] FAIL: ${msg}`);
  process.exit(1);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  if (!ES_URL || !KBN_URL || !API_KEY) {
    die("set ES_URL, KBN_URL, and API_KEY (or KBN_API_KEY/ES_API_KEY) in env");
  }

  const creds = {
    name: "smoke",
    elasticsearchUrl: ES_URL,
    kibanaUrl: KBN_URL,
    elasticsearchApiKey: API_KEY,
  };
  const esClient = createEsClient(creds);
  const kibanaClient = createKibanaClient(creds);
  const svc = new CorrelationService({ esClient, kibanaClient });

  // 1. Resolve a case report_id.
  let reportId = process.env.REPORT_ID?.trim() || "";
  let reportTitle = "";
  if (!reportId) {
    console.log(`[smoke] no REPORT_ID given — picking a diamond_suitable report from ${INDEX} …`);
    const resp = await esClient.post<{
      hits: { hits: Array<{ _source: { content_fingerprint: string; content?: { title?: string } } }> };
    }>(`/${INDEX}/_search`, {
      size: 1,
      _source: ["content_fingerprint", "content.title"],
      query: { term: { "extracted.diamond.suitable": { value: true } } },
    });
    const hit = resp.data?.hits?.hits?.[0];
    if (!hit) die(`no diamond_suitable report found in ${INDEX}`);
    reportId = hit._source.content_fingerprint;
    reportTitle = hit._source.content?.title ?? "";
  }
  console.log(`[smoke] case report_id=${reportId}${reportTitle ? `  ("${reportTitle}")` : ""}  depth=${DEPTH}`);

  // 2. Trigger the workflow (async).
  const t0 = Date.now();
  const run = await svc.runCorrelation({ report_id: reportId, depth: DEPTH });
  console.log(`[smoke] correlate → run_id=${run.run_id}  workflow=${run.workflow_id}`);

  // 3. Poll until the run record is persisted with a terminal status.
  let record: Awaited<ReturnType<CorrelationService["getCorrelationRun"]>> | null = null;
  while (Date.now() - t0 < POLL_TIMEOUT_MS) {
    await sleep(POLL_INTERVAL_MS);
    const r = await svc.getCorrelationRun(run.run_id);
    const elapsed = Math.round((Date.now() - t0) / 1000);
    if (!r.found) {
      console.log(`[smoke]   +${elapsed}s  pending …`);
      continue;
    }
    console.log(`[smoke]   +${elapsed}s  status=${r.status}`);
    if (r.status && r.status !== "pending" && r.status !== "running") {
      record = r;
      break;
    }
  }
  if (!record) die(`timed out after ${POLL_TIMEOUT_MS / 1000}s waiting for run ${run.run_id}`);

  // 4. Report counts / trace and validate the render-shape transform.
  console.log(`[smoke] counts:`, JSON.stringify(record.counts ?? {}));
  console.log(`[smoke] trace :`, JSON.stringify(record.trace ?? {}));
  if (record.error) console.log(`[smoke] error :`, record.error);

  const { findings, unresolved } = workflowFindingsToRenderShape(record.findings, record.picks);
  if (findings === null) {
    console.log(`[smoke] no synthesized report (status=${record.status}, depth=${record.depth}) — findings=null.`);
    console.log(`[smoke] PASS: live correlate→poll round-trip OK (non-full/no-synthesis path).`);
    return;
  }
  if (unresolved.length > 0) {
    console.log(`[smoke] WARNING: ${unresolved.length} candidate title(s) did not resolve to a report id:`);
    for (const u of unresolved) console.log(`[smoke]   ${u.where}[${u.index}] "${u.title}"`);
  }

  const leads = (findings.leads as Array<Record<string, unknown>>) ?? [];
  const noMatch = (findings.no_match as Array<Record<string, unknown>>) ?? [];
  const meta = (findings.candidate_meta as Record<string, unknown>) ?? {};
  console.log(`[smoke] findings: ${leads.length} lead(s), ${noMatch.length} no_match, ${Object.keys(meta).length} candidate_meta`);

  // Assertions on the transform.
  const leftoverTitles = leads.filter((l) => Array.isArray((l as { candidate_titles?: unknown }).candidate_titles));
  if (leftoverTitles.length > 0) die("transform left candidate_titles on a lead (should be stripped)");

  for (const [i, l] of leads.entries()) {
    const ids = (l as { candidate_ids?: unknown }).candidate_ids;
    if (!Array.isArray(ids) || ids.length === 0) {
      die(`lead[${i}] has no candidate_ids after transform`);
    }
    console.log(`[smoke]   lead[${i}] "${(l as { title?: string }).title}" → candidate_ids=${JSON.stringify(ids)}`);
  }

  console.log(`\n[smoke] PASS: live correlate→poll→transform round-trip OK.`);
}

main().catch((err) => die(String(err?.stack || err?.message || err)));

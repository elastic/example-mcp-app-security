/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Paint-by-numbers canvas generator.
 *
 * Cursor renders MCP app views inline in chat only — it has no side-panel
 * surface for MCP UI resources. The Cursor-native "beside the chat" surface is
 * a Canvas, which must be a self-contained .canvas.tsx file (no fetch). So we
 * keep the presentation as a fixed template (correlation-report.canvas.tmpl)
 * and inject a run's render-shape findings as the data ("the numbers").
 *
 * This is the exact `findings` object get_correlation_run hands to
 * render_correlation (counts + trace + run_meta + anchors_searched +
 * anchor_trail folded in), stamped into the template's FINDINGS constant.
 *
 * Creds from env: ES_URL, KBN_URL, API_KEY (KBN_API_KEY/ES_API_KEY accepted).
 * Output dir: CORRELATION_CANVAS_DIR (or CANVAS_DIR) — point it at your Cursor
 * project's canvases dir.
 * Usage: RUN_ID=<execution id> npx tsx scripts/gen-correlation-canvas.ts
 */

import { createEsClient } from "../src/elastic/es-client/index.js";
import { createKibanaClient } from "../src/elastic/kibana-client/index.js";
import { CorrelationService } from "../src/elastic/service/correlationService.js";
import { workflowFindingsToRenderShape } from "../src/tools/correlation.js";
import { emitCorrelationCanvas } from "../src/canvas/correlation-canvas.js";

const API_KEY = process.env.API_KEY || process.env.KBN_API_KEY || process.env.ES_API_KEY || "";
const ES_URL = process.env.ES_URL || "";
const KBN_URL = process.env.KBN_URL || "";
const RUN_ID = process.env.RUN_ID?.trim() || "";
// Same env the MCP server reads; point it at your Cursor project's canvases dir.
const CANVAS_DIR = process.env.CORRELATION_CANVAS_DIR || process.env.CANVAS_DIR || "";

function die(msg: string): never {
  console.error(`[gen-canvas] FAIL: ${msg}`);
  process.exit(1);
}

async function main() {
  if (!ES_URL || !KBN_URL || !API_KEY) die("set ES_URL, KBN_URL, API_KEY in env");
  if (!RUN_ID) die("set RUN_ID in env");
  if (!CANVAS_DIR) die("set CORRELATION_CANVAS_DIR (or CANVAS_DIR) to your canvases output dir");

  const creds = {
    name: "gen-canvas",
    elasticsearchUrl: ES_URL,
    kibanaUrl: KBN_URL,
    elasticsearchApiKey: API_KEY,
    sslVerify: process.env.ELASTIC_SSL_VERIFY === "false" ? false : true,
  };
  const svc = new CorrelationService({
    esClient: createEsClient(creds),
    kibanaClient: createKibanaClient(creds),
  });

  const record = await svc.getCorrelationRun(RUN_ID);
  if (!record.found) die(`run ${RUN_ID} not found / still pending`);

  const { findings } = workflowFindingsToRenderShape(record.findings, record.picks, {
    trace: record.trace,
    counts: record.counts,
    run: { run_id: record.run_id ?? RUN_ID, depth: record.depth, status: record.status },
    caseAnchors: record.case?.anchors,
    caseVertexSignal: record.case?.vertex_signal as Record<string, string> | undefined,
    pool: record.candidates,
  });
  if (!findings) {
    die(`run ${RUN_ID} has no synthesized findings (depth=${record.depth}, status=${record.status})`);
  }

  const emitted = emitCorrelationCanvas({
    findings,
    runId: record.run_id ?? RUN_ID,
    caseTitle: record.case?.title,
    dir: CANVAS_DIR,
  });
  if (!emitted) die("no output dir resolved");
  console.log(`[gen-canvas] wrote ${emitted.file}`);
  console.log(`[gen-canvas] run ${RUN_ID} · depth ${record.depth} · ${record.counts?.leads ?? 0} leads`);
}

main().catch((err) => die(String(err?.stack || err?.message || err)));

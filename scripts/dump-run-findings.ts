/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Dump the render-shape CorrelationFindings for a completed run to stdout.
 * This is the EXACT object get_correlation_run hands to render_correlation
 * (counts + trace + run_meta + anchors_searched + anchor_trail folded in), so
 * it can be embedded verbatim into the correlation-report Cursor canvas demo.
 *
 * Creds from env: ES_URL, KBN_URL, API_KEY (KBN_API_KEY/ES_API_KEY accepted).
 * Usage: RUN_ID=<execution id> npx tsx scripts/dump-run-findings.ts
 */

import { createEsClient } from "../src/elastic/es-client/index.js";
import { createKibanaClient } from "../src/elastic/kibana-client/index.js";
import { CorrelationService } from "../src/elastic/service/correlationService.js";
import { workflowFindingsToRenderShape } from "../src/tools/correlation.js";

const API_KEY = process.env.API_KEY || process.env.KBN_API_KEY || process.env.ES_API_KEY || "";
const ES_URL = process.env.ES_URL || "";
const KBN_URL = process.env.KBN_URL || "";
const RUN_ID = process.env.RUN_ID?.trim() || "";

function die(msg: string): never {
  console.error(`[dump] FAIL: ${msg}`);
  process.exit(1);
}

async function main() {
  if (!ES_URL || !KBN_URL || !API_KEY) die("set ES_URL, KBN_URL, API_KEY in env");
  if (!RUN_ID) die("set RUN_ID in env");

  const creds = {
    name: "dump",
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
    pool: record.candidates,
  });
  if (findings === null) die(`run ${RUN_ID} has no synthesized findings (depth=${record.depth}, status=${record.status})`);

  process.stdout.write(JSON.stringify(findings, null, 2));
}

main().catch((err) => die(String(err?.stack || err?.message || err)));

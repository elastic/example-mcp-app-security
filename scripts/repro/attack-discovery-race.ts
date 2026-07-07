/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Ground-truth repro for github.com/elastic/example-mcp-app-security#46.
 *
 * Triggers `generate-attack-discovery`, then polls `get-generation-status`
 * (Kibana's own generation envelope — includes a `discoveries` count once
 * terminal) side-by-side with `triage-attack-discoveries` /
 * `poll-discoveries` (the ES|QL-based tools) in the same time window, on
 * every tick. This isolates which of the two hypotheses from the issue is
 * responsible for "0 discoveries":
 *
 *   1. Race: `get-generation-status` reports `discoveries: N > 0` (Kibana's
 *      own view of what it wrote) while `triage-attack-discoveries` still
 *      returns `total: 0` for several ticks after the generation reaches a
 *      terminal status. This is the "retrieval hasn't caught up yet" case
 *      the UI paper over by polling both independently.
 *   2. Swallowed error: `triage-attack-discoveries` returns `total: 0` even
 *      several ticks *after* the generation's terminal status, while
 *      `get-generation-status` reports `discoveries: N > 0` the whole time.
 *      Run with MCP_DEBUG_ESQL=1 to surface the underlying safeEsql()
 *      failure that would otherwise be silently swallowed.
 *   3. Neither: both report 0 — the generation itself found nothing (not a
 *      bug in this app).
 *
 * Usage:
 *   MCP_DEBUG_ESQL=1 npx tsx scripts/repro/attack-discovery-race.ts
 *
 * Requires a shared clusters file (see docs/testing-shared-instance.md).
 */

import { createServer } from "../../src/server.js";
import { connectInProcess } from "../../src/test/helpers/integrationServer.js";
import {
  applySharedClusterEnv,
  formatSkipMessage,
  resolveSharedClustersFile,
} from "../e2e/env.js";
import { selectConnector, type Generation } from "../e2e/attackDiscoveryPoll.js";

const POLL_INTERVAL_MS = 5_000;
const MAX_TICKS = 24; // 2 minutes at 5s intervals

function parseToolJson(result: { content?: Array<{ type: string; text?: string }>; isError?: boolean }): unknown {
  const text = result.content?.find((c) => c.type === "text")?.text;
  if (!text) throw new Error("tool response missing text content");
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`tool response not JSON (isError=${result.isError}): ${text}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(): Promise<number> {
  const resolved = resolveSharedClustersFile();
  if (!resolved) {
    console.log(formatSkipMessage());
    return 1;
  }

  applySharedClusterEnv(resolved);
  console.log(`Using clusters file (${resolved.source}): ${resolved.clustersFile}`);

  const harness = await connectInProcess(createServer());
  try {
    const callTool = async (name: string, args: Record<string, unknown>) =>
      parseToolJson(await harness.client.callTool({ name, arguments: args }));

    const connectorNameOverride = process.env.REPRO_CONNECTOR_NAME;
    console.log("\n=== Step 1: list-ai-connectors ===");
    const connectors = (await callTool("list-ai-connectors", {})) as {
      id: string;
      name: string;
      actionTypeId: string;
    }[];
    console.log(`Found ${connectors.length} connector(s): ${connectors.map((c) => c.name).join(", ")}`);
    if (connectors.length === 0) {
      console.error("No AI connectors configured on this cluster — cannot repro generation path.");
      return 1;
    }
    const connector = selectConnector(connectors, connectorNameOverride);
    if (!connector) {
      console.error(`Connector override "${connectorNameOverride}" not found among: ${connectors.map((c) => c.name).join(", ")}`);
      return 1;
    }
    console.log(`Using connector: ${connector.name} (${connector.actionTypeId})`);

    console.log("\n=== Step 2: generate-attack-discovery ===");
    const genResult = (await callTool("generate-attack-discovery", {
      connectorName: connector.name,
      start: "now-7d",
      end: "now",
    })) as { execution_uuid?: string; error?: string };

    if (genResult.error) {
      console.error(`generate-attack-discovery returned an error: ${genResult.error}`);
      return 1;
    }
    const executionUuid = genResult.execution_uuid;
    console.log(`Generation started: execution_uuid=${executionUuid}`);

    console.log(
      `\n=== Step 3: poll get-generation-status vs triage-attack-discoveries every ${POLL_INTERVAL_MS / 1000}s ===\n`
    );
    console.log(
      [
        "tick",
        "elapsed_s",
        "gen_status",
        "gen_discoveries",
        "triage_total",
        "poll_total",
      ].join("\t")
    );

    const startTime = Date.now();
    let sawTerminal = false;
    let ticksSinceTerminal = 0;

    for (let tick = 0; tick < MAX_TICKS; tick++) {
      const elapsedS = Math.round((Date.now() - startTime) / 1000);

      const genStatus = (await callTool("get-generation-status", {
        size: 5,
        start: "now-1h",
      })) as { generations?: Generation[] };
      const gen = (genStatus.generations || []).find(
        (g) => g.execution_uuid === executionUuid
      );

      const triage = (await callTool("triage-attack-discoveries", {
        days: 7,
        limit: 50,
      })) as { total?: number };

      const poll = (await callTool("poll-discoveries", {
        days: 7,
        limit: 50,
      })) as { total?: number };

      console.log(
        [
          tick,
          elapsedS,
          gen?.status ?? "not-found",
          gen?.discoveries ?? "n/a",
          triage.total ?? 0,
          poll.total ?? 0,
        ].join("\t")
      );

      const isTerminal = gen?.status === "succeeded" || gen?.status === "failed";
      if (isTerminal) {
        if (!sawTerminal) {
          sawTerminal = true;
          console.log(
            `\n>>> Generation reached terminal status "${gen?.status}" at tick ${tick} (${elapsedS}s). Kibana reports discoveries=${gen?.discoveries}.`
          );
          if ((gen?.discoveries ?? 0) > 0 && (triage.total ?? 0) === 0) {
            console.log(
              ">>> MISMATCH at terminal tick: get-generation-status says discoveries>0 but triage-attack-discoveries says total=0. Continuing to poll to see if this is transient (race) or persistent (swallowed error / other bug)."
            );
          } else if ((gen?.discoveries ?? 0) === 0) {
            console.log(">>> Generation itself found 0 discoveries — not a retrieval bug for this run.");
            break;
          } else {
            console.log(">>> triage-attack-discoveries already matches get-generation-status. No repro this run.");
            break;
          }
        }
        ticksSinceTerminal++;
        if (ticksSinceTerminal >= 4) {
          if ((triage.total ?? 0) === 0 && (gen?.discoveries ?? 0) > 0) {
            console.log(
              "\n>>> CONFIRMED: 4+ ticks after terminal status, triage-attack-discoveries STILL returns 0 while Kibana reports discoveries>0."
            );
            console.log(
              ">>> This points to hypothesis #2 (silent error swallowing in safeEsql) or a query/index mismatch, NOT a transient race."
            );
            console.log(">>> Re-run with MCP_DEBUG_ESQL=1 to see the underlying safeEsql failure (if any) and the [getDiscoveries] row-count log lines.");
          } else {
            console.log("\n>>> triage-attack-discoveries caught up — this looks like the race hypothesis (#1), not a swallowed error.");
          }
          break;
        }
      }

      await sleep(POLL_INTERVAL_MS);
    }

    if (!sawTerminal) {
      console.log("\n>>> Generation never reached a terminal status within the poll window — increase MAX_TICKS or check connector health.");
    }

    return 0;
  } finally {
    await harness.close();
  }
}

main().catch((err: unknown) => {
  console.error("Repro script crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});

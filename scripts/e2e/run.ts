/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Live E2E against a shared Elastic serverless cluster:
 * seed sample data (when sparse), then exercise MCP tools end-to-end.
 */

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createServer } from "../../src/server.js";
import { connectInProcess } from "../../src/test/helpers/integrationServer.js";
import {
  applySharedClusterEnv,
  formatSkipMessage,
  resolveSharedClustersFile,
} from "./env.js";
import { pollGenerationUntilTerminal, selectConnector } from "./attackDiscoveryPoll.js";

const SEED_SCENARIO = "ransomware-kill-chain";
const SEED_COUNT = 25;
const MIN_DOCS_BEFORE_SEED = 10;

function parseToolJson(result: { content?: Array<{ type: string; text?: string }> }): unknown {
  const text = result.content?.find((c) => c.type === "text")?.text;
  if (!text) throw new Error("tool response missing text content");
  return JSON.parse(text);
}

// Generation runs two sequential LLM round-trips (generate, then refine), each
// through whatever connector is configured. Behind a slow/overloaded provider
// this observably took ~10 minutes end-to-end in local testing, well past a
// naive "1-3 minutes" assumption - so default generously and let CI override
// via MCP_E2E_ATTACK_DISCOVERY_TIMEOUT_MS if its connector is faster.
const ATTACK_DISCOVERY_GEN_TIMEOUT_MS = Number(
  process.env.MCP_E2E_ATTACK_DISCOVERY_TIMEOUT_MS ?? 15 * 60_000
);
const ATTACK_DISCOVERY_POLL_INTERVAL_MS = 10_000;

/**
 * Smoke-test the on-demand Attack Discovery generation path end-to-end:
 * list connectors -> trigger generation -> poll get-generation-status to a
 * terminal state -> assert the generation itself reports discoveries.
 *
 * This exists to catch regressions like
 * github.com/elastic/example-mcp-app-security#46, where a `camelCase`/
 * `snake_case` param mismatch silently truncated the anonymization field
 * list feeding the LLM prompt, starving generation of context. Skips
 * cleanly (does not fail the run) when no AI connector is configured on
 * the shared cluster, since connector provisioning is out of this script's
 * control.
 */
async function runAttackDiscoverySmoke(client: Client): Promise<void> {
  if (process.env.MCP_E2E_ATTACK_DISCOVERY_SKIP === "1") {
    console.log("attack-discovery smoke: SKIPPED (MCP_E2E_ATTACK_DISCOVERY_SKIP=1)");
    return;
  }

  const callTool = async (name: string, args: Record<string, unknown>) =>
    parseToolJson(await client.callTool({ name, arguments: args }));

  const connectors = (await callTool("list-ai-connectors", {})) as {
    id: string;
    name: string;
    actionTypeId: string;
  }[];

  if (connectors.length === 0) {
    console.log("attack-discovery smoke: SKIPPED (no AI connector configured on this cluster)");
    return;
  }

  const connector = selectConnector(connectors, process.env.MCP_E2E_CONNECTOR_NAME);
  if (!connector) {
    console.log("attack-discovery smoke: SKIPPED (connector override not found)");
    return;
  }
  console.log(`attack-discovery smoke: using connector ${connector.name} (${connector.actionTypeId})`);

  const genResult = (await callTool("generate-attack-discovery", {
    connectorName: connector.name,
    start: "now-7d",
    end: "now",
  })) as { execution_uuid?: string; error?: string };

  if (genResult.error || !genResult.execution_uuid) {
    throw new Error(`generate-attack-discovery failed: ${genResult.error ?? "no execution_uuid returned"}`);
  }
  console.log(`attack-discovery smoke: generation started execution_uuid=${genResult.execution_uuid}`);

  const { gen, timedOut } = await pollGenerationUntilTerminal(callTool, genResult.execution_uuid, {
    intervalMs: ATTACK_DISCOVERY_POLL_INTERVAL_MS,
    maxTicks: Math.ceil(ATTACK_DISCOVERY_GEN_TIMEOUT_MS / ATTACK_DISCOVERY_POLL_INTERVAL_MS),
    onTick: (g, tick, elapsedS) => {
      console.log(`attack-discovery smoke: tick=${tick} elapsed_s=${elapsedS} status=${g?.status ?? "not-found"}`);
    },
  });

  if (timedOut) {
    throw new Error(
      `attack-discovery generation did not reach a terminal status within ${ATTACK_DISCOVERY_GEN_TIMEOUT_MS / 1000}s`
    );
  }
  if (gen?.status === "failed") {
    throw new Error(`attack-discovery generation failed: ${gen.reason ?? "unknown reason"}`);
  }

  console.log(`attack-discovery smoke: status=${gen?.status} discoveries=${gen?.discoveries}`);

  // This is the actual regression check for #46: against seeded sample data
  // (a full ransomware kill-chain, correlated alerts), a healthy pipeline
  // should find at least one discovery. A silent param-casing mismatch that
  // starves the LLM prompt of anonymization fields reproduces as
  // succeeded-but-empty here, not as an HTTP error — so this assertion,
  // not just a terminal-status check, is what catches it.
  if ((gen?.discoveries ?? 0) === 0) {
    throw new Error(
      "attack-discovery generation succeeded but found 0 discoveries against seeded sample data. " +
        "This is the failure mode of #46 (silent param truncation starving the LLM prompt of context) " +
        "— check anonymization-field param casing in attackDiscoveryClient.ts before assuming an LLM fluke. " +
        "Set MCP_E2E_ATTACK_DISCOVERY_SKIP=1 to bypass this assertion if it proves too flaky."
    );
  }
}

async function main(): Promise<number> {
  if (process.env.MCP_E2E_SKIP === "1") {
    console.log("MCP E2E skipped (MCP_E2E_SKIP=1)");
    return 0;
  }

  const resolved = resolveSharedClustersFile();
  if (!resolved) {
    console.log(formatSkipMessage());
    return process.env.MCP_E2E_REQUIRED === "1" ? 1 : 0;
  }

  applySharedClusterEnv(resolved);
  console.log(`MCP E2E using clusters file (${resolved.source}): ${resolved.clustersFile}`);

  const harness = await connectInProcess(createServer());
  try {
    const tools = await harness.client.listTools();
    const names = new Set(tools.tools.map((t) => t.name));
    for (const required of ["poll-alerts", "list-cases", "find-rules", "list-indices"]) {
      if (!names.has(required)) {
        throw new Error(`missing tool on server: ${required}`);
      }
    }

    const existing = parseToolJson(
      await harness.client.callTool({ name: "check-existing-sample-data", arguments: {} })
    ) as { totalDocs?: number };

    if ((existing.totalDocs ?? 0) < MIN_DOCS_BEFORE_SEED) {
      console.log(`Seeding scenario ${SEED_SCENARIO} (${SEED_COUNT} events)...`);
      const seeded = parseToolJson(
        await harness.client.callTool({
          name: "generate-scenario",
          arguments: { scenario: SEED_SCENARIO, count: SEED_COUNT },
        })
      ) as { indexed?: number; scenario?: string };
      console.log(`Seed complete: indexed=${seeded.indexed ?? "?"} scenario=${seeded.scenario ?? SEED_SCENARIO}`);
    } else {
      console.log(`Sample data present (totalDocs=${existing.totalDocs}) — skipping seed`);
    }

    const alerts = parseToolJson(
      await harness.client.callTool({
        name: "poll-alerts",
        arguments: { limit: 5, days: 7 },
      })
    ) as { alerts?: unknown[]; total?: number };
    console.log(`poll-alerts: total=${(alerts as { total?: number }).total ?? alerts.alerts?.length ?? 0}`);

    const cases = parseToolJson(
      await harness.client.callTool({ name: "list-cases", arguments: { page: 1, perPage: 5 } })
    ) as { cases?: unknown[]; total?: number };
    console.log(`list-cases: total=${cases.total ?? cases.cases?.length ?? 0}`);

    const rules = parseToolJson(
      await harness.client.callTool({
        name: "find-rules",
        arguments: { page: 1, perPage: 5 },
      })
    ) as { total?: number; data?: unknown[] };
    console.log(`find-rules: total=${rules.total ?? rules.data?.length ?? 0}`);

    const indices = parseToolJson(
      await harness.client.callTool({ name: "list-indices", arguments: {} })
    ) as { indices?: unknown[] };
    console.log(`list-indices: count=${indices.indices?.length ?? 0}`);

    await runAttackDiscoverySmoke(harness.client);

    console.log("MCP E2E_PASS");
    return 0;
  } finally {
    await harness.close();
  }
}

main().catch((err: unknown) => {
  console.error("MCP E2E failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});

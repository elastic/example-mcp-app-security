/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Shared polling helper for Attack Discovery on-demand generation, used by
 * both `scripts/e2e/run.ts` (CI smoke test) and
 * `scripts/repro/attack-discovery-race.ts` (manual repro for
 * github.com/elastic/example-mcp-app-security#46).
 */

export interface Generation {
  execution_uuid: string;
  status: string;
  discoveries?: number;
  start?: string;
  end?: string;
  reason?: string;
}

export interface PollGenerationResult {
  /** The matching generation record on the last tick, if any. */
  gen: Generation | undefined;
  /** Number of ticks elapsed (poll intervals consumed). */
  ticksElapsed: number;
  /** True if `maxTicks` was exhausted without reaching a terminal status. */
  timedOut: boolean;
}

export interface PollGenerationOptions {
  intervalMs?: number;
  maxTicks?: number;
  /** Called once per tick, before the terminal-status check. */
  onTick?: (gen: Generation | undefined, tick: number, elapsedS: number) => void;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Poll `get-generation-status` until the generation matching `executionUuid`
 * reaches a terminal status (`succeeded` / `failed`), or `maxTicks` is
 * exhausted.
 */
export async function pollGenerationUntilTerminal(
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
  executionUuid: string,
  opts: PollGenerationOptions = {}
): Promise<PollGenerationResult> {
  const intervalMs = opts.intervalMs ?? 5_000;
  const maxTicks = opts.maxTicks ?? 24; // 2 minutes at the default interval
  const startTime = Date.now();

  for (let tick = 0; tick < maxTicks; tick++) {
    const elapsedS = Math.round((Date.now() - startTime) / 1000);
    const genStatus = (await callTool("get-generation-status", {
      size: 5,
      start: "now-1h",
    })) as { generations?: Generation[] };
    const gen = (genStatus.generations || []).find(
      (g) => g.execution_uuid === executionUuid
    );

    opts.onTick?.(gen, tick, elapsedS);

    if (gen?.status === "succeeded" || gen?.status === "failed") {
      return { gen, ticksElapsed: tick, timedOut: false };
    }

    await sleep(intervalMs);
  }

  return { gen: undefined, ticksElapsed: maxTicks, timedOut: true };
}

/** Pick a connector by exact name match, falling back to the first available. */
export function selectConnector<T extends { name: string }>(
  connectors: T[],
  nameOverride?: string
): T | undefined {
  return (
    (nameOverride && connectors.find((c) => c.name === nameOverride)) ||
    connectors[0]
  );
}

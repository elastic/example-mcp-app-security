/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export interface EvalScenario {
  readonly id: string;
  readonly tool: string;
  readonly arguments: Record<string, unknown>;
  readonly assert: (body: unknown) => void;
}

export const LIVE_EVAL_SCENARIOS: EvalScenario[] = [
  {
    id: "tools-list-nonempty",
    tool: "generate-sample-data",
    arguments: {},
    assert(body) {
      const b = body as { status?: string; scenarios?: string[] };
      if (b.status !== "ready" || !Array.isArray(b.scenarios) || b.scenarios.length < 3) {
        throw new Error("generate-sample-data ready envelope invalid");
      }
    },
  },
  {
    id: "poll-alerts-shape",
    tool: "poll-alerts",
    arguments: { limit: 3, days: 14 },
    assert(body) {
      const b = body as { alerts?: unknown[] };
      if (!Array.isArray(b.alerts)) throw new Error("poll-alerts missing alerts array");
    },
  },
  {
    id: "list-cases-shape",
    tool: "list-cases",
    arguments: { page: 1, perPage: 3 },
    assert(body) {
      const b = body as { cases?: unknown[] };
      if (!Array.isArray(b.cases)) throw new Error("list-cases missing cases array");
    },
  },
  {
    id: "find-rules-shape",
    tool: "find-rules",
    arguments: { page: 1, perPage: 3 },
    assert(body) {
      const b = body as { data?: unknown[] };
      if (!Array.isArray(b.data)) throw new Error("find-rules missing data array");
    },
  },
  {
    id: "list-indices-shape",
    tool: "list-indices",
    arguments: {},
    assert(body) {
      const b = body as { indices?: unknown[] };
      if (!Array.isArray(b.indices)) throw new Error("list-indices missing indices array");
    },
  },
];

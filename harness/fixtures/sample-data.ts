/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Fixtures for the Sample Data view.
 */

export default {
  "check-existing-sample-data": () => ({
    totalDocs: 4820,
    totalAlerts: 612,
    existingRules: 14,
    byScenario: {
      "credential-access": { events: 812, alerts: 98 },
      "execution-chain": { events: 1120, alerts: 144 },
      "persistence": { events: 600, alerts: 52 },
      "exfiltration": { events: 412, alerts: 41 },
      "lateral-movement": { events: 906, alerts: 172 },
      "discovery": { events: 970, alerts: 105 },
    },
  }),
  "create-rules-for-scenario": (args: { scenario: string }) => ({
    scenario: args.scenario,
    created: Math.floor(Math.random() * 3) + 2,
  }),
  "generate-scenario": (args: { scenario: string; count: number }) => ({
    scenario: args.scenario,
    indexed: args.count,
    alerts: Math.floor(args.count * 0.18),
  }),
  "cleanup-sample-data": () => ({ deleted: 4820 }),
} as Record<string, unknown | ((args: any) => unknown)>;

export const variants: Record<string, Record<string, unknown>> = {
  empty: {
    "check-existing-sample-data": {
      totalDocs: 0,
      totalAlerts: 0,
      existingRules: 0,
      byScenario: {},
    },
  },
};

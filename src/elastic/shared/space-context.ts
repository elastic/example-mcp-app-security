/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { DEFAULT_SPACE_ID } from "../../shared/spaces.js";
import { pathSegment } from "./path-segment.js";

/**
 * Kibana space for the tool call in progress. Tool handlers run inside
 * `runInSpace`, so clients and services can read the space without it being
 * threaded through every signature. Outside a tool call (startup, telemetry)
 * the default space applies.
 */
const storage = new AsyncLocalStorage<string>();

export function runInSpace<T>(spaceId: string, fn: () => T): T {
  return storage.run(spaceId, fn);
}

export function currentSpaceId(): string {
  return storage.getStore() ?? DEFAULT_SPACE_ID;
}

/** Prefix a Kibana path with `/s/<space>`; the default space has no prefix. */
export function kibanaSpacePath(path: string, spaceId: string = currentSpaceId()): string {
  return spaceId === DEFAULT_SPACE_ID ? path : `/s/${pathSegment(spaceId)}${path}`;
}

/** Params for reads on a space index Kibana may not have created yet. */
export const MISSING_INDEX_IS_EMPTY: { params: Record<string, string> } = {
  params: { ignore_unavailable: "true", allow_no_indices: "true" },
};

/** Security Solution indices, which Kibana suffixes with the space ID. */
export const spaceIndices = {
  alerts: (spaceId: string = currentSpaceId()): string =>
    `.alerts-security.alerts-${spaceId}`,
  attackDiscovery: (spaceId: string = currentSpaceId()): string =>
    `.alerts-security.attack.discovery.alerts-${spaceId}`,
  adhocAttackDiscovery: (spaceId: string = currentSpaceId()): string =>
    `.adhoc.alerts-security.attack.discovery.alerts-${spaceId}`,
  riskScoreLatest: (spaceId: string = currentSpaceId()): string =>
    `risk-score.risk-score-latest-${spaceId}`,
};

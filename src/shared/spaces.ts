/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Kibana space contract shared by the server tools and the views.
 */

export const DEFAULT_SPACE_ID = "default";

/** Kibana space IDs: lowercase letters, digits, `_` and `-`. */
export const SPACE_ID_PATTERN = /^[a-z0-9_-]+$/;

/** Optional per-call argument every space-aware tool accepts. */
export const SPACE_ARG = "space";

export const LIST_SPACES_TOOL = "list-spaces";
export const COUNT_BY_SPACE_TOOL = "count-by-space";

export interface SpaceSummary {
  readonly id: string;
  readonly name: string;
  readonly color?: string;
  readonly initials?: string;
}

/** Result of `list-spaces`. */
export interface ListSpacesResult {
  /** Space from the cluster config; used when a call doesn't pass `space`. */
  readonly configured: string;
  /** Spaces the API key can access, as reported by Kibana. */
  readonly spaces: SpaceSummary[];
}

export type SpaceCountKind = "alerts" | "discoveries";

/** Result of `count-by-space`. */
export interface SpaceCountsResult {
  readonly kind: SpaceCountKind;
  readonly days: number;
  /** Space ID to count; spaces with no matches may be omitted. */
  readonly counts: Record<string, number>;
}

export function isValidSpaceId(value: string): boolean {
  return SPACE_ID_PATTERN.test(value);
}

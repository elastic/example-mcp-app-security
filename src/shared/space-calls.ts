/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { extractCallResult } from "./extract-tool-text";
import {
  COUNT_BY_SPACE_TOOL,
  LIST_SPACES_TOOL,
  SPACE_ARG,
  type ListSpacesResult,
  type SpaceCountsResult,
  type SpaceSummary,
} from "./spaces";

/** Tools that are not scoped to the session space. */
const UNSCOPED_TOOLS: ReadonlySet<string> = new Set([
  "report-analytics-event",
  LIST_SPACES_TOOL,
  COUNT_BY_SPACE_TOOL,
]);

export interface ToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

/**
 * Adds `space: active` to a tool call when the analyst is viewing a space
 * other than the configured one. Calls that already pass `space`, and
 * unscoped tools, are returned unchanged.
 */
export function withSpaceArg<P extends ToolCallParams>(
  params: P,
  active: string,
  configured: string,
): P {
  if (!active || active === configured) return params;
  if (UNSCOPED_TOOLS.has(params.name)) return params;
  if (params.arguments?.[SPACE_ARG] !== undefined) return params;
  return { ...params, arguments: { ...params.arguments, [SPACE_ARG]: active } };
}

function parseToolJson(result: unknown): unknown {
  if (result && typeof result === "object" && (result as { isError?: unknown }).isError) {
    return null;
  }
  const text = extractCallResult(result);
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isSpaceSummary(value: unknown): value is SpaceSummary {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return typeof v.id === "string" && typeof v.name === "string";
}

/** Parses a `list-spaces` result; returns null when it's missing or malformed. */
export function parseListSpacesResult(result: unknown): ListSpacesResult | null {
  const data = parseToolJson(result);
  if (!data || typeof data !== "object") return null;
  const { configured, spaces } = data as Record<string, unknown>;
  if (typeof configured !== "string" || !Array.isArray(spaces)) return null;
  return {
    configured,
    spaces: spaces.filter(isSpaceSummary).map(({ id, name, color, initials }) => ({
      id,
      name,
      ...(typeof color === "string" ? { color } : {}),
      ...(typeof initials === "string" ? { initials } : {}),
    })),
  };
}

/** Parses a `count-by-space` result; returns null when it's missing or malformed. */
export function parseSpaceCountsResult(result: unknown): SpaceCountsResult | null {
  const data = parseToolJson(result);
  if (!data || typeof data !== "object") return null;
  const { kind, days, counts } = data as Record<string, unknown>;
  if (kind !== "alerts" && kind !== "discoveries") return null;
  if (!counts || typeof counts !== "object") return null;
  const numeric: Record<string, number> = {};
  for (const [id, n] of Object.entries(counts)) {
    if (typeof n === "number" && Number.isFinite(n)) numeric[id] = n;
  }
  return { kind, days: typeof days === "number" ? days : 0, counts: numeric };
}

export function spaceDisplayName(spaces: readonly SpaceSummary[], id: string): string {
  return spaces.find((s) => s.id === id)?.name ?? id;
}

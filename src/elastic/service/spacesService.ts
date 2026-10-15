/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  ListSpacesResult,
  SpaceCountKind,
  SpaceCountsResult,
} from "../../shared/spaces.js";
import type { SpacesClient } from "../client/spacesClient.js";

interface CountTarget {
  readonly indexPattern: string;
  /** Matches the view's default look-back so the counts line up with what it shows. */
  readonly defaultDays: number;
}

const COUNT_TARGETS: Record<SpaceCountKind, CountTarget> = {
  alerts: {
    indexPattern: ".alerts-security.alerts-*",
    defaultDays: 7,
  },
  discoveries: {
    indexPattern:
      ".alerts-security.attack.discovery.alerts-*,.adhoc.alerts-security.attack.discovery.alerts-*",
    defaultDays: 1,
  },
};

const MAX_SPACES = 100;

interface SpacesServiceOptions {
  readonly spacesClient: SpacesClient;
  /** Space from the cluster config, reported back by {@link SpacesService.listSpaces}. */
  readonly configuredSpace: string;
}

/**
 * Business logic for Kibana space discovery.
 *
 * Lists the spaces the API key can access and counts open alerts or attack
 * discoveries per space with a single cross-space query. Stateless — safe
 * to construct per request.
 */
export class SpacesService {
  constructor(private readonly options: SpacesServiceOptions) {}

  async listSpaces(): Promise<ListSpacesResult> {
    const spaces = await this.options.spacesClient.listSpaces();
    return { configured: this.options.configuredSpace, spaces };
  }

  /**
   * Count open alerts or attack discoveries per space over the last `days`
   * days (default: 7 for alerts, 1 for discoveries). Spaces with no matches
   * are omitted.
   */
  async countBySpace(
    kind: SpaceCountKind,
    days?: number
  ): Promise<SpaceCountsResult> {
    const { indexPattern, defaultDays } = COUNT_TARGETS[kind];
    const lookback = days ?? defaultDays;

    const response = await this.options.spacesClient.countBySpace(indexPattern, {
      size: 0,
      track_total_hits: false,
      query: {
        bool: {
          filter: [
            { term: { "kibana.alert.workflow_status": "open" } },
            { range: { "@timestamp": { gte: `now-${lookback}d` } } },
          ],
        },
      },
      aggs: {
        by_space: { terms: { field: "kibana.space_ids", size: MAX_SPACES } },
      },
    });

    const buckets = response.aggregations?.by_space?.buckets ?? [];
    return {
      kind,
      days: lookback,
      counts: Object.fromEntries(buckets.map((b) => [b.key, b.doc_count])),
    };
  }
}

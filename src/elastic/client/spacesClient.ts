/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaClient } from "../kibana-client/index.js";

const SPACES_API = "/api/spaces/space";
const KIBANA_API_VERSION = "2023-10-31";

const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/**
 * Raw Kibana space record. The endpoint returns more fields than this
 * (color, initials, imageUrl, solution, …); we keep only what the model
 * needs to pick a `namespace` for follow-up case calls.
 */
export interface KibanaSpace {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly disabledFeatures?: readonly string[];
  readonly _reserved?: boolean;
}

interface SpacesClientOptions {
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Kibana's Spaces API. Used to enumerate the spaces
 * an API key can see so the model can fan case tools out across them.
 */
export class SpacesClient {
  constructor(private readonly options: SpacesClientOptions) {}

  /** GET `/api/spaces/space` — list every space the caller can read. */
  async listSpaces(): Promise<KibanaSpace[]> {
    const { data } = await this.options.kibanaClient.get<KibanaSpace[]>(
      SPACES_API,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }
}

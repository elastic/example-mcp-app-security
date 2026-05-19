/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SpacesClient } from "../client/spacesClient.js";

/** Compact projection sent to the model — drops fields it doesn't need to plan with. */
export interface SpaceSummary {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
}

interface SpacesServiceOptions {
  readonly spacesClient: SpacesClient;
}

/**
 * Business logic for Kibana Spaces. The only operation is "list the spaces
 * the API key can see" — the model uses this to fan case tools out across
 * namespaces when the user asks for a deployment-wide view.
 */
export class SpacesService {
  constructor(private readonly options: SpacesServiceOptions) {}

  async listSpaces(): Promise<SpaceSummary[]> {
    const spaces = await this.options.spacesClient.listSpaces();
    return spaces.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description,
    }));
  }
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsClient } from "../es-client/index.js";

/** Domain node in an investigation graph. */
export interface GraphNode {
  id: string;
  type: "user" | "host" | "ip" | "process" | "alert";
  value: string;
  metadata?: Record<string, unknown>;
}

/** Domain edge in an investigation graph. */
export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

/** Result of {@link InvestigateService.investigateEntity}. */
export interface InvestigationResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** Typed envelope returned by `POST /_query?format=json`. */
export interface EsqlEnvelope {
  columns: { name: string }[];
  values: unknown[][];
}

interface InvestigateClientOptions {
  readonly esClient: EsClient;
}

/**
 * Typed transport for the ES|QL queries that back graph investigations.
 *
 * Bound to a single cluster via the injected {@link EsClient}. Maps 1:1 to
 * `POST /_query?format=json`. The service builds the queries.
 */
export class InvestigateClient {
  constructor(private readonly options: InvestigateClientOptions) {}

  /** POST `/_query?format=json` */
  async runEsql(query: string): Promise<EsqlEnvelope> {
    const { data } = await this.options.esClient.post<EsqlEnvelope>(
      "/_query",
      { query },
      { params: { format: "json" } }
    );
    return data;
  }
}

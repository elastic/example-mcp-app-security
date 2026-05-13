/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsqlResult } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";

interface EsqlClientOptions {
  readonly esClient: EsClient;
}

/**
 * Typed transport for the Elasticsearch ES|QL endpoint.
 *
 * Bound to a single cluster via the injected {@link EsClient}. Maps 1:1 to a
 * single ES API call (`POST /_query?format=json`). Query construction is the
 * caller's responsibility — this client is purely a transport.
 */
export class EsqlClient {
  constructor(private readonly options: EsqlClientOptions) {}

  /** POST `/_query?format=json` */
  async executeEsql(query: string): Promise<EsqlResult> {
    const { data } = await this.options.esClient.post<EsqlResult>(
      "/_query",
      { query },
      { params: { format: "json" } }
    );
    return data;
  }
}

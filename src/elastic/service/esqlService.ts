/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsqlResult } from "../../shared/types.js";
import type { EsqlClient } from "../client/esqlClient.js";

interface EsqlServiceOptions {
  readonly esqlClient: EsqlClient;
}

/**
 * Business-logic facade for ES|QL execution.
 *
 * Currently a thin passthrough to {@link EsqlClient.executeEsql}. Defined as
 * its own service so callers depend on the same client/service pattern as
 * every other domain module.
 */
export class EsqlService {
  constructor(private readonly options: EsqlServiceOptions) {}

  executeEsql(query: string): Promise<EsqlResult> {
    return this.options.esqlClient.executeEsql(query);
  }
}

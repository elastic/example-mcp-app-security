/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { esRequest } from "./client.js";
import type { EsqlResult } from "../shared/types.js";

export async function executeEsql(query: string): Promise<EsqlResult> {
  const result = await esRequest<EsqlResult>("/_query", {
    body: { query },
    params: { format: "json" },
  });
  return result;
}

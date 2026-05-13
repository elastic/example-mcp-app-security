/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { EsqlService } from "./esqlService.js";
import { createMockEsqlClient } from "../../test/helpers/mockServiceClients.js";

describe("EsqlService", () => {
  it("delegates executeEsql straight through to the client", async () => {
    const esqlClient = createMockEsqlClient();
    const result = { columns: [{ name: "x", type: "long" }], values: [[1]] };
    vi.mocked(esqlClient.executeEsql).mockResolvedValueOnce(result);

    const service = new EsqlService({ esqlClient });
    const out = await service.executeEsql("FROM x");

    expect(esqlClient.executeEsql).toHaveBeenCalledWith("FROM x");
    expect(out).toBe(result);
  });
});

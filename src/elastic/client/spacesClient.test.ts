/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { SpacesClient, type KibanaSpace } from "./spacesClient.js";
import {
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const KIBANA_HEADERS = { "elastic-api-version": "2023-10-31" };

describe("SpacesClient", () => {
  it("listSpaces GETs /api/spaces/space with the Kibana API version header", async () => {
    const kibanaClient = createMockKibanaClient();
    const spaces: KibanaSpace[] = [
      { id: "default", name: "Default", _reserved: true },
      { id: "soc", name: "SOC", description: "Security ops" },
    ];
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope(spaces));

    const client = new SpacesClient({ kibanaClient });
    const out = await client.listSpaces();

    expect(kibanaClient.get).toHaveBeenCalledWith("/api/spaces/space", {
      headers: KIBANA_HEADERS,
    });
    expect(out).toBe(spaces);
  });
});

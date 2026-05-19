/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { SpacesService } from "./spacesService.js";
import { createMockSpacesClient } from "../../test/helpers/mockServiceClients.js";

describe("SpacesService", () => {
  it("projects the raw space records down to { id, name, description }", async () => {
    const spacesClient = createMockSpacesClient();
    vi.mocked(spacesClient.listSpaces).mockResolvedValueOnce([
      {
        id: "default",
        name: "Default",
        description: "Default space",
        disabledFeatures: [],
        _reserved: true,
      },
      { id: "soc", name: "SOC" },
    ]);

    const service = new SpacesService({ spacesClient });
    const out = await service.listSpaces();

    expect(out).toEqual([
      { id: "default", name: "Default", description: "Default space" },
      { id: "soc", name: "SOC", description: undefined },
    ]);
  });

  it("propagates errors from the client", async () => {
    const spacesClient = createMockSpacesClient();
    vi.mocked(spacesClient.listSpaces).mockRejectedValueOnce(
      new Error("403 Forbidden")
    );

    const service = new SpacesService({ spacesClient });
    await expect(service.listSpaces()).rejects.toThrow("403 Forbidden");
  });
});

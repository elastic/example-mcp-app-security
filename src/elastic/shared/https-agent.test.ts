/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import type { ClusterCredentials } from "../credential-client/index.js";
import { createHttpsAgent } from "./https-agent.js";

function creds(
  overrides: Partial<ClusterCredentials> = {}
): ClusterCredentials {
  return {
    name: "primary",
    elasticsearchUrl: "https://es.example.com",
    kibanaUrl: "https://kb.example.com",
    elasticsearchApiKey: "key-1",
    sslVerify: true,
    ...overrides,
  };
}

describe("createHttpsAgent", () => {
  it("returns undefined when both URLs are http://", () => {
    expect(
      createHttpsAgent(
        creds({
          elasticsearchUrl: "http://es.example.com",
          kibanaUrl: "http://kb.example.com",
        })
      )
    ).toBeUndefined();
  });

  it("creates an agent with rejectUnauthorized true by default", () => {
    const agent = createHttpsAgent(creds());
    expect(agent).toBeDefined();
    expect(agent!.options.rejectUnauthorized).toBe(true);
    expect(agent!.options.ca).toBeUndefined();
  });

  it("creates an agent with rejectUnauthorized false when sslVerify is false", () => {
    const agent = createHttpsAgent(creds({ sslVerify: false }));
    expect(agent).toBeDefined();
    expect(agent!.options.rejectUnauthorized).toBe(false);
  });

  it("attaches a custom CA bundle when caCert is set", () => {
    const caCert = Buffer.from("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
    const agent = createHttpsAgent(creds({ caCert }));
    expect(agent).toBeDefined();
    expect(agent!.options.ca).toBe(caCert);
    expect(agent!.options.rejectUnauthorized).toBe(true);
  });

  it("creates an agent when only one URL is https://", () => {
    const agent = createHttpsAgent(
      creds({
        elasticsearchUrl: "http://es.example.com",
        kibanaUrl: "https://kb.example.com",
      })
    );
    expect(agent).toBeDefined();
  });
});

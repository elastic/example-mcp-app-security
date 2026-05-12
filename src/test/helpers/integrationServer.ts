/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export interface IntegrationHarness {
  readonly client: Client;
  readonly server: McpServer;
  /** Tear down both ends. Idempotent. */
  readonly close: () => Promise<void>;
}

/**
 * Wire a real MCP `Client` to the supplied `McpServer` via a linked pair of
 * {@link InMemoryTransport}s. Both ends are connected by the time this
 * resolves and the client has completed the initialisation handshake.
 */
export async function connectInProcess(
  server: McpServer
): Promise<IntegrationHarness> {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  const client = new Client(
    { name: "integration-test-client", version: "0.0.0" },
    { capabilities: {} }
  );

  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);

  return {
    client,
    server,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

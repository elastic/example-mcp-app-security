/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi, type Mock } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  MCP_APP_BOOTSTRAP_KIND,
  type McpAppBootstrapEnvelope,
  type ViewBootstrapPayloads,
} from "../../shared/mcp-app-bootstrap.js";
import type { ViewId } from "../../shared/analytics-events.js";

/**
 * Captured tool registration. The third argument of `registerTool` is the
 * callback that the MCP runtime invokes when a client calls the tool — tests
 * fish this out to exercise tool behaviour without standing up a real server.
 */
export interface CapturedTool {
  readonly name: string;
  readonly config: {
    title?: string;
    description?: string;
    inputSchema?: unknown;
    outputSchema?: unknown;
    annotations?: unknown;
    _meta?: Record<string, unknown>;
  };
  readonly callback: (
    args: Record<string, unknown>
  ) => Promise<{
    content: { type: "text"; text: string }[];
  }>;
}

/**
 * Captured resource registration. `readCallback` returns the HTML body the
 * MCP host should serve for the resource URI.
 */
export interface CapturedResource {
  readonly name: string;
  readonly uri: string;
  readonly config: { mimeType?: string };
  readonly readCallback: () => Promise<{
    contents: { uri: string; mimeType: string; text: string }[];
  }>;
}

/** Test double for {@link McpServer} that captures tool / resource registrations. */
export interface MockMcpServer
  extends Pick<McpServer, "registerTool" | "registerResource"> {
  readonly tools: Map<string, CapturedTool>;
  readonly resources: Map<string, CapturedResource>;
  /** Convenience: get a captured tool, throwing if missing. */
  readonly tool: (name: string) => CapturedTool;
  /** Convenience: get a captured resource, throwing if missing. */
  readonly resource: (uri: string) => CapturedResource;
  readonly registerTool: Mock;
  readonly registerResource: Mock;
}

/**
 * Create an in-memory {@link McpServer} double. `registerTool` /
 * `registerResource` calls are recorded on the returned object instead of
 * being forwarded to a real transport.
 */
export function createMockMcpServer(): MockMcpServer {
  const tools = new Map<string, CapturedTool>();
  const resources = new Map<string, CapturedResource>();

  const registerTool = vi.fn(
    (
      name: string,
      config: CapturedTool["config"],
      callback: CapturedTool["callback"]
    ) => {
      tools.set(name, { name, config, callback });
      return { name, config, callback };
    }
  );

  const registerResource = vi.fn(
    (
      name: string,
      uri: string,
      config: CapturedResource["config"],
      readCallback: CapturedResource["readCallback"]
    ) => {
      resources.set(uri, { name, uri, config, readCallback });
      return { name, uri, config, readCallback };
    }
  );

  return {
    tools,
    resources,
    tool: (name: string) => {
      const captured = tools.get(name);
      if (!captured) {
        throw new Error(
          `No tool registered with name "${name}". Registered: ${[...tools.keys()].join(", ") || "<none>"}`
        );
      }
      return captured;
    },
    resource: (uri: string) => {
      const captured = resources.get(uri);
      if (!captured) {
        throw new Error(
          `No resource registered with uri "${uri}". Registered: ${[...resources.keys()].join(", ") || "<none>"}`
        );
      }
      return captured;
    },
    registerTool: registerTool as unknown as Mock,
    registerResource: registerResource as unknown as Mock,
  } as unknown as MockMcpServer;
}

/**
 * Helper: parse the JSON envelope returned by every tool callback. Tools
 * always emit a single `text` content block whose body is JSON; tests are
 * almost universally interested in the parsed value, not the wrapper.
 */
export function parseToolText<T = unknown>(result: {
  content: { type: "text"; text: string }[];
}): T {
  if (result.content.length !== 1 || result.content[0].type !== "text") {
    throw new Error(
      `Expected tool result with a single text block, got: ${JSON.stringify(result)}`
    );
  }
  return JSON.parse(result.content[0].text) as T;
}

export function parseBootstrapToolText<V extends ViewId>(
  result: {
    content: { type: "text"; text: string }[];
  },
  viewId: V,
): ViewBootstrapPayloads[V] {
  const envelope = parseToolText<McpAppBootstrapEnvelope<V>>(result);
  if (envelope.kind !== MCP_APP_BOOTSTRAP_KIND) {
    throw new Error(
      `Expected bootstrap envelope, got kind ${String(envelope.kind)}`,
    );
  }
  if (envelope.viewId !== viewId) {
    throw new Error(
      `Expected bootstrap for ${viewId}, got ${String(envelope.viewId)}`,
    );
  }
  return envelope.payload as ViewBootstrapPayloads[V];
}

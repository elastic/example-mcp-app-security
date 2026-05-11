#!/usr/bin/env node
/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import "dotenv/config";
import express from "express";
import cors from "cors";
import {
  createCredentialClient,
  type CredentialClient,
} from "./src/elastic/credential-client/index.js";
import { createServer } from "./src/server.js";

const isStdio = process.argv.includes("--stdio");

/**
 * Format a startup error so it's actually useful in the MCP host's log
 * pane.
 *
 * Two subtleties make this trickier than it looks:
 *
 *  1. A thrown Error from an ES-module top-level-await can be swallowed
 *     before the runtime flushes its default report, so we write our own
 *     readable message instead of relying on Node's unhandled-rejection
 *     printer.
 *  2. When stderr is a *pipe* (which it always is under an MCP host like
 *     Claude Desktop), `console.error` is non-blocking. Calling
 *     `process.exit()` immediately after writing terminates the process
 *     before libuv flushes the pipe, so the host sees only
 *     "Server transport closed unexpectedly" with no body. We work around
 *     this by waiting for the write callback (or a short timeout) before
 *     exiting, which is enough to get the message into the host's log.
 */
function fatal(prefix: string, err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error && err.stack ? `\n${err.stack}` : "";
  const line = `[elastic-security] ${prefix}: ${message}${stack}\n`;

  let exited = false;
  const exit = (): void => {
    if (exited) return;
    exited = true;
    process.exit(1);
  };

  // Belt-and-braces: exit even if the write callback never fires (e.g.
  // pipe already closed). 1s is long enough for any reasonable flush
  // and short enough that the host doesn't sit waiting on us.
  const timer = setTimeout(exit, 1000);
  timer.unref();

  process.stderr.write(line, exit);
}

// Built once at startup so HTTP mode doesn't re-read CLUSTERS_FILE and
// re-run Zod on every POST /mcp, and so config errors fail before the
// listener binds.
let credentialClient: CredentialClient;
try {
  credentialClient = createCredentialClient();
} catch (err) {
  fatal("startup failed", err);
  // `fatal()` schedules `process.exit(1)`; rethrow so TS sees this branch
  // as terminating and treats `credentialClient` as definitely assigned.
  throw err;
}

if (isStdio) {
  try {
    const server = createServer({ credentialClient });
    const transport = new StdioServerTransport();
    await server.connect(transport);
  } catch (err) {
    fatal("startup failed", err);
  }
} else {
  const app = express();
  app.use(cors());
  app.use(express.json());

  // Fresh McpServer + transport per request, per the MCP TS SDK's
  // stateless HTTP guidance. Heavy startup work is hoisted to
  // `credentialClient` above so this stays cheap.
  app.post("/mcp", async (req, res) => {
    try {
      const server = createServer({ credentialClient });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[elastic-security] request failed: ${message}`);
      if (!res.headersSent) {
        res.writeHead(500).end(JSON.stringify({ error: message }));
      }
    }
  });

  app.get("/mcp", async (req, res) => {
    res.writeHead(405).end(JSON.stringify({ error: "Use POST for MCP requests" }));
  });

  app.delete("/mcp", async (req, res) => {
    res.writeHead(405).end(JSON.stringify({ error: "Session management not supported in stateless mode" }));
  });

  const port = parseInt(process.env.PORT || "3001", 10);
  const httpServer = app.listen(port, () => {
    console.log(`Elastic Security MCP App server running on http://localhost:${port}/mcp`);
  });
  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Error: Port ${port} is already in use. Set a different port with the PORT environment variable.`);
    } else {
      console.error(`Server error: ${err.message}`);
    }
    process.exit(1);
  });
}

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
import { createServer } from "./src/server.js";

const isStdio = process.argv.includes("--stdio");

/**
 * Format a startup error so it's actually useful in the MCP host's log
 * pane. The host only echoes stderr — a thrown Error from inside an
 * ES-module top-level-await can be swallowed before the runtime flushes
 * its default report — so we write our own readable message first, then
 * exit non-zero.
 */
function fatal(prefix: string, err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error && err.stack ? `\n${err.stack}` : "";
  console.error(`[elastic-security] ${prefix}: ${message}${stack}`);
  process.exit(1);
}

if (isStdio) {
  try {
    const server = createServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
  } catch (err) {
    fatal("startup failed", err);
  }
} else {
  const app = express();
  app.use(cors());
  app.use(express.json());

  app.post("/mcp", async (req, res) => {
    try {
      const server = createServer();
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

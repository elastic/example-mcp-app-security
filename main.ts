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

if (isStdio) {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
} else {
  const app = express();
  app.use(cors());
  app.use(express.json());

  app.post("/mcp", async (req, res) => {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
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

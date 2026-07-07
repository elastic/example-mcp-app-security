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
import { createEsClient } from "./src/elastic/es-client/index.js";
import { createKibanaClient } from "./src/elastic/kibana-client/index.js";
import {
  createAnalyticsClient,
  createContextLoader,
  type AnalyticsClient,
} from "./src/elastic/analytics/index.js";
import { TelemetryConfigClient } from "./src/elastic/client/telemetryConfigClient.js";
import { TelemetryService } from "./src/elastic/service/telemetryService.js";
import { createServer } from "./src/server.js";
import { createStderrLogger } from "./src/shared/logger.js";
import { readPackageVersion } from "./src/shared/package-version.js";

const isStdio = process.argv.includes("--stdio");
const logger = createStderrLogger();
const serverLogger = logger.child("elastic-security");
const telemetryLogger = logger.child("telemetry");

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
//
// The whole block is `fatal()`-guarded because any synchronous throw
// during initialisation — bad cluster config, EBT shipper construction
// failure, or anything similar — must surface as a readable line in
// the MCP host's log pane rather than the opaque "Server transport
// closed unexpectedly" the host reports for a silent crash.
let credentialClient: CredentialClient;
let analytics: AnalyticsClient;
try {
  credentialClient = createCredentialClient();

  for (const summary of credentialClient.list()) {
    const cluster = credentialClient.get(summary.name);
    if (cluster.sslVerify === false) {
      serverLogger.warn(
        `cluster "${cluster.name}": TLS certificate verification is DISABLED. ` +
          `This is insecure and should only be used with trusted self-signed dev clusters.`
      );
    } else if (cluster.caCert) {
      serverLogger.info(
        `cluster "${cluster.name}": using custom CA bundle for TLS verification`
      );
    }
  }

  // Default cluster is the analytics seed: telemetry config opt-in is
  // read from it and cluster/license context is pulled from it. These
  // are constructed once at startup and shared across all per-request
  // servers in HTTP mode so the EBT shipper has a single context view.
  const defaultCredentials = credentialClient.get();
  analytics = createAnalyticsClient({
    mcpAppVersion: readPackageVersion(import.meta.url),
    logger: telemetryLogger,
  });

  const defaultEsClient = createEsClient(defaultCredentials);
  const defaultKibanaClient = createKibanaClient(defaultCredentials);
  const telemetryConfigClient = new TelemetryConfigClient({
    kibanaClient: defaultKibanaClient,
  });
  const telemetryService = new TelemetryService({
    telemetryConfigClient,
    analytics,
    logger: telemetryLogger,
  });
  const contextLoader = createContextLoader({
    esClient: defaultEsClient,
    analytics,
    logger: telemetryLogger,
  });

  // Fire-and-forget: a slow or unreachable Kibana / Elasticsearch must
  // never block transport bind. The analytics client starts opted-out
  // at construction and only flips on after the Kibana telemetry
  // config fetch succeeds with `optIn === true`, so the gap is safe.
  void Promise.allSettled([
    telemetryService.applyOptIn(),
    contextLoader.loadAndApply(),
  ]);
} catch (err) {
  fatal("startup failed", err);
  // `fatal()` schedules `process.exit(1)`; rethrow so TS sees this
  // branch as terminating and treats `credentialClient` / `analytics`
  // as definitely assigned.
  throw err;
}

/**
 * Upper bound on how long we'll wait for `analytics.shutdown()` to
 * drain in-flight EBT requests before we exit. If the telemetry
 * endpoint is unreachable the shipper can sit waiting indefinitely;
 * the host (Claude Desktop / Cursor) would then escalate to SIGKILL.
 * 1.5 s is generous for a fire-and-forget queue and short enough that
 * the host never notices.
 */
const ANALYTICS_SHUTDOWN_TIMEOUT_MS = 1500;

// Flush any queued events before the host kills us. Both signals are
// handled because Claude Desktop sends SIGINT to the stdio child but
// container runtimes send SIGTERM. The closure captures a single
// in-flight Promise so re-entry (e.g. SIGTERM followed by SIGINT)
// returns the same handle rather than starting a second drain.
const shutdown = ((): ((signal: NodeJS.Signals) => Promise<void>) => {
  let started: Promise<void> | null = null;
  return (signal) => {
    if (started) return started;
    started = (async () => {
      try {
        let flushed = false;
        await Promise.race([
          analytics.shutdown().then(() => {
            flushed = true;
          }),
          new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, ANALYTICS_SHUTDOWN_TIMEOUT_MS);
            timer.unref();
          }),
        ]);
        if (flushed) {
          serverLogger.info("analytics events flushed before shutdown");
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        serverLogger.error(`analytics shutdown failed: ${message}`);
      }
      // Re-raise with the conventional 128+signo exit code so init
      // systems can tell us apart from a normal `exit(0)`.
      process.exit(signal === "SIGINT" ? 130 : 143);
    })();
    return started;
  };
})();

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    void shutdown(signal);
  });
}

if (isStdio) {
  try {
    const server = createServer({ credentialClient, analytics });
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
      const server = createServer({ credentialClient, analytics });
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      serverLogger.error(`request failed: ${message}`);
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
    serverLogger.info(`HTTP server running on http://localhost:${port}/mcp`);
  });
  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      serverLogger.error(`Port ${port} is already in use. Set a different port with the PORT environment variable.`);
    } else {
      serverLogger.error(`Server error: ${err.message}`);
    }
    process.exit(1);
  });
}

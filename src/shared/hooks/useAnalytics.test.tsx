/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useEffect, useRef, type ReactNode } from "react";
import { describe, it, expect, vi } from "vitest";
import { render, waitFor, act } from "@testing-library/react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import {
  McpAppContext,
  type McpAppContextValue,
} from "./McpAppContext.js";
import { useAnalytics } from "./useAnalytics.js";
import type { ViewId } from "../analytics-events.js";

interface FakeApp {
  callServerTool: ReturnType<typeof vi.fn>;
}

function makeContext({
  app,
  connected,
}: {
  app: FakeApp | null;
  connected: boolean;
}): McpAppContextValue {
  // `useAnalytics` doesn't subscribe to the pub/sub channels, so stubs
  // that return a no-op unsubscribe are enough. Tests that exercise the
  // channels (multi-subscriber fan-out, replay) live in
  // `useMcpAppEvents.test.tsx`.
  return {
    app: app as unknown as McpApp | null,
    getApp: () => app as unknown as McpApp | null,
    connected,
    subscribeToToolResult: () => () => {},
    subscribeToConnect: () => () => {},
  };
}

function Wrapper({
  value,
  children,
}: {
  value: McpAppContextValue;
  children: ReactNode;
}) {
  return <McpAppContext.Provider value={value}>{children}</McpAppContext.Provider>;
}

function ProbeOnMount({ viewId }: { viewId: "alert-triage" | "threat-hunt" }) {
  const { trackViewRendered } = useAnalytics();
  useEffect(() => {
    trackViewRendered(viewId);
  }, [trackViewRendered, viewId]);
  return null;
}

describe("useAnalytics", () => {
  it("calls report-analytics-event once when mounted with a ready connection", async () => {
    const callServerTool = vi.fn().mockResolvedValue(undefined);
    const ctx = makeContext({ app: { callServerTool }, connected: true });

    render(
      <Wrapper value={ctx}>
        <ProbeOnMount viewId="alert-triage" />
      </Wrapper>,
    );

    await waitFor(() => expect(callServerTool).toHaveBeenCalledTimes(1));
    expect(callServerTool).toHaveBeenCalledWith({
      name: "report-analytics-event",
      arguments: { eventType: "view_rendered", viewId: "alert-triage" },
    });
  });

  it("buffers calls issued pre-connect and flushes them when connected flips true", async () => {
    const callServerTool = vi.fn().mockResolvedValue(undefined);

    const { rerender } = render(
      <Wrapper value={makeContext({ app: { callServerTool }, connected: false })}>
        <ProbeOnMount viewId="alert-triage" />
      </Wrapper>,
    );

    // Effect ran but the hook saw connected=false → buffered, nothing shipped.
    expect(callServerTool).not.toHaveBeenCalled();

    // ProbeOnMount's `useRef` state must survive the rerender, so we have to
    // re-render the *same* component instance with a new context value.
    rerender(
      <Wrapper value={makeContext({ app: { callServerTool }, connected: true })}>
        <ProbeOnMount viewId="alert-triage" />
      </Wrapper>,
    );

    await waitFor(() => expect(callServerTool).toHaveBeenCalledTimes(1));
    expect(callServerTool).toHaveBeenCalledWith({
      name: "report-analytics-event",
      arguments: { eventType: "view_rendered", viewId: "alert-triage" },
    });
  });

  it("forwards every call — the hook does NOT dedupe, the consumer owns that", async () => {
    // The hook is a thin wrapper that returns `trackViewRendered`; it
    // intentionally doesn't carry hidden per-viewId dedupe state.
    // Consumers that need single-fire-per-mount semantics wrap the
    // call in their own effect with a `useRef` guard.
    const callServerTool = vi.fn().mockResolvedValue(undefined);
    const ctx = makeContext({ app: { callServerTool }, connected: true });

    function DoubleFire() {
      const { trackViewRendered } = useAnalytics();
      const ran = useRef(false);
      useEffect(() => {
        if (!ran.current) {
          ran.current = true;
          trackViewRendered("threat-hunt");
          trackViewRendered("threat-hunt");
        }
      }, [trackViewRendered]);
      return null;
    }

    render(
      <Wrapper value={ctx}>
        <DoubleFire />
      </Wrapper>,
    );

    await waitFor(() => expect(callServerTool).toHaveBeenCalledTimes(2));
    expect(callServerTool).toHaveBeenNthCalledWith(1, {
      name: "report-analytics-event",
      arguments: { eventType: "view_rendered", viewId: "threat-hunt" },
    });
    expect(callServerTool).toHaveBeenNthCalledWith(2, {
      name: "report-analytics-event",
      arguments: { eventType: "view_rendered", viewId: "threat-hunt" },
    });
  });

  it("keeps a stable trackViewRendered identity across context churn", async () => {
    // Consumers wire `trackViewRendered` into a useEffect dep list.
    // The hook reads `connected` / `getApp` through refs so the
    // function identity doesn't change when the provider rebuilds
    // its context value (e.g. when `connected` flips true) — otherwise
    // a mount-effect would re-fire and we'd get duplicate emissions
    // *despite* the consumer only intending one.
    const callServerTool = vi.fn().mockResolvedValue(undefined);

    const identities: Array<(viewId: ViewId) => void> = [];

    function Probe() {
      const { trackViewRendered } = useAnalytics();
      identities.push(trackViewRendered);
      return null;
    }

    const { rerender } = render(
      <Wrapper value={makeContext({ app: { callServerTool }, connected: false })}>
        <Probe />
      </Wrapper>,
    );

    rerender(
      <Wrapper value={makeContext({ app: { callServerTool }, connected: true })}>
        <Probe />
      </Wrapper>,
    );

    expect(identities.length).toBeGreaterThanOrEqual(2);
    // Same identity across the connected=false → connected=true transition.
    expect(identities[0]).toBe(identities[identities.length - 1]);
  });

  it("swallows failures from app.callServerTool so views are never broken by telemetry", async () => {
    const callServerTool = vi
      .fn()
      .mockRejectedValue(new Error("transport closed"));
    const ctx = makeContext({ app: { callServerTool }, connected: true });

    render(
      <Wrapper value={ctx}>
        <ProbeOnMount viewId="alert-triage" />
      </Wrapper>,
    );

    await act(async () => {
      // Let the rejected promise settle before we assert.
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(callServerTool).toHaveBeenCalled();
  });
});

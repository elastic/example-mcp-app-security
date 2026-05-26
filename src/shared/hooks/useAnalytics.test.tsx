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
import type { AnalyticsEvent, ViewId } from "../analytics-events.js";

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
    bootstrapState: { status: "idle" },
    subscribeToToolResult: () => () => {},
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

function ProbeOnMount({ viewId }: { viewId: ViewId }) {
  const { trackEvent } = useAnalytics();
  useEffect(() => {
    trackEvent({ eventType: "view_rendered", viewId });
  }, [trackEvent, viewId]);
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
    const callServerTool = vi.fn().mockResolvedValue(undefined);
    const ctx = makeContext({ app: { callServerTool }, connected: true });

    function DoubleFire() {
      const { trackEvent } = useAnalytics();
      const ran = useRef(false);
      useEffect(() => {
        if (!ran.current) {
          ran.current = true;
          trackEvent({ eventType: "view_rendered", viewId: "threat-hunt" });
          trackEvent({ eventType: "view_rendered", viewId: "threat-hunt" });
        }
      }, [trackEvent]);
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

  it("keeps a stable trackEvent identity across context churn", async () => {
    const callServerTool = vi.fn().mockResolvedValue(undefined);

    const identities: Array<(event: AnalyticsEvent) => void> = [];

    function Probe() {
      const { trackEvent } = useAnalytics();
      identities.push(trackEvent);
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
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(callServerTool).toHaveBeenCalled();
  });
});

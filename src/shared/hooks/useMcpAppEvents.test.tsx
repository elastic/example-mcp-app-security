/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useState, type ReactNode } from "react";
import { describe, it, expect, vi } from "vitest";
import { render, act } from "@testing-library/react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import {
  McpAppContext,
  type McpAppContextValue,
  type OnToolResult,
  type ToolResultParams,
} from "./McpAppContext.js";
import { createMcpAppBootstrap } from "../mcp-app-bootstrap.js";
import { useMcpAppBootstrap, useMcpAppEvents } from "./useMcpApp.js";

/**
 * Build a controllable context value that mirrors `McpAppProvider`'s
 * pub/sub registry without dragging in `new McpApp()` or a real
 * transport. Exposes `triggerToolResult` so tests can drive events
 * deterministically, while bootstrap state is provided directly on the
 * context value the same way late subscribers would read it in the app.
 */
function buildTestContext({
  appStub,
  connected = true,
  bootstrapState = { status: "idle" } as const,
}: {
  appStub: McpApp;
  connected?: boolean;
  bootstrapState?: McpAppContextValue["bootstrapState"];
}) {
  const toolResultListeners = new Set<OnToolResult>();

  const ctx: McpAppContextValue = {
    app: appStub,
    getApp: () => appStub,
    connected,
    bootstrapState,
    subscribeToToolResult: (listener) => {
      toolResultListeners.add(listener);
      return () => {
        toolResultListeners.delete(listener);
      };
    },
  };

  return {
    ctx,
    triggerToolResult(params: ToolResultParams) {
      for (const l of [...toolResultListeners]) l(params, appStub);
    },
    toolResultCount: () => toolResultListeners.size,
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

const stubApp = {} as unknown as McpApp;
const fakeToolResult = {} as unknown as ToolResultParams;

describe("useMcpAppEvents", () => {
  it("fans onToolResult out to every subscriber in the tree", () => {
    const { ctx, triggerToolResult } = buildTestContext({ appStub: stubApp });

    const a = vi.fn();
    const b = vi.fn();
    const c = vi.fn();

    function Probe({ cb }: { cb: OnToolResult }) {
      useMcpAppEvents({ onToolResult: cb });
      return null;
    }

    render(
      <Wrapper value={ctx}>
        <Probe cb={a} />
        <Probe cb={b} />
        <Probe cb={c} />
      </Wrapper>,
    );

    act(() => {
      triggerToolResult(fakeToolResult);
    });

    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    expect(c).toHaveBeenCalledTimes(1);
  });

  it("reads the ready bootstrap payload synchronously for late subscribers", () => {
    const { ctx } = buildTestContext({
      appStub: stubApp,
      bootstrapState: {
        status: "ready",
        envelope: createMcpAppBootstrap("alert-triage", {
          summary: {
            total: 1,
            bySeverity: { high: 1 },
            byRule: [],
            byHost: [],
            alerts: [],
          },
          params: { days: 7, limit: 50 },
          verdicts: [],
        }),
      },
    });

    function LateProbe() {
      const bootstrap = useMcpAppBootstrap("alert-triage");
      return <div>{bootstrap.status === "ready" ? String(bootstrap.payload.summary.total) : "nope"}</div>;
    }

    const { getByText } = render(
      <Wrapper value={ctx}>
        <LateProbe />
      </Wrapper>,
    );

    expect(getByText("1")).toBeTruthy();
  });

  it("surfaces a bootstrap mismatch as an error state", () => {
    const { ctx } = buildTestContext({
      appStub: stubApp,
      bootstrapState: {
        status: "ready",
        envelope: createMcpAppBootstrap("case-management", {
          total: 0,
          cases: [],
          params: {},
        }),
      },
    });

    function Probe() {
      const bootstrap = useMcpAppBootstrap("alert-triage");
      return <div>{bootstrap.status === "error" ? bootstrap.reason : "ok"}</div>;
    }

    const { getByText } = render(
      <Wrapper value={ctx}>
        <Probe />
      </Wrapper>,
    );

    expect(getByText(/does not match alert-triage/)).toBeTruthy();
  });

  it("uses the latest callback identity without re-subscribing on every render", () => {
    const { ctx, triggerToolResult, toolResultCount } = buildTestContext({
      appStub: stubApp,
    });

    const calls: number[] = [];

    function Probe() {
      const [n, setN] = useState(0);
      const onToolResult = useCallback<OnToolResult>(() => {
        calls.push(n);
      }, [n]);
      useMcpAppEvents({ onToolResult });
      return (
        <button type="button" onClick={() => setN((x) => x + 1)}>
          {n}
        </button>
      );
    }

    const { container } = render(
      <Wrapper value={ctx}>
        <Probe />
      </Wrapper>,
    );

    expect(toolResultCount()).toBe(1);

    act(() => {
      triggerToolResult(fakeToolResult);
    });
    expect(calls).toEqual([0]);

    act(() => {
      container.querySelector("button")!.click();
    });
    act(() => {
      triggerToolResult(fakeToolResult);
    });

    expect(toolResultCount()).toBe(1);
    expect(calls).toEqual([0, 1]);
  });

  it("unsubscribes on unmount", () => {
    const { ctx, toolResultCount } = buildTestContext({
      appStub: stubApp,
    });

    function Probe() {
      useMcpAppEvents({ onToolResult: () => {} });
      return null;
    }

    const { unmount } = render(
      <Wrapper value={ctx}>
        <Probe />
      </Wrapper>,
    );

    expect(toolResultCount()).toBe(1);

    unmount();

    expect(toolResultCount()).toBe(0);
  });

  it("throws a clear error when used outside <McpAppProvider>", () => {
    function Probe() {
      useMcpAppEvents({});
      return null;
    }

    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      expect(() => render(<Probe />)).toThrow(/McpAppProvider/);
    } finally {
      spy.mockRestore();
    }
  });
});

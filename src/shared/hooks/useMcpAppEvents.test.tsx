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
  type OnConnect,
  type OnToolResult,
  type ToolResultParams,
} from "./McpAppContext.js";
import { useMcpAppEvents } from "./useMcpApp.js";

/**
 * Build a controllable context value that mirrors `McpAppProvider`'s
 * pub/sub registry without dragging in `new McpApp()` or its
 * `connect()` timer. Exposes `triggerToolResult` / `triggerConnect`
 * helpers so tests can drive events deterministically.
 */
function buildTestContext({
  appStub,
  connected = true,
  replayConnect,
}: {
  appStub: McpApp;
  connected?: boolean;
  /** If set, late subscribers replay this firing immediately. */
  replayConnect?: { gotResult: boolean };
}) {
  const toolResultListeners = new Set<OnToolResult>();
  const connectListeners = new Set<OnConnect>();

  const ctx: McpAppContextValue = {
    app: appStub,
    getApp: () => appStub,
    connected,
    subscribeToToolResult: (listener) => {
      toolResultListeners.add(listener);
      return () => {
        toolResultListeners.delete(listener);
      };
    },
    subscribeToConnect: (listener) => {
      connectListeners.add(listener);
      if (replayConnect) {
        listener(appStub, replayConnect.gotResult);
      }
      return () => {
        connectListeners.delete(listener);
      };
    },
  };

  return {
    ctx,
    triggerToolResult(params: ToolResultParams) {
      for (const l of [...toolResultListeners]) l(params, appStub);
    },
    triggerConnect(gotResult: boolean) {
      for (const l of [...connectListeners]) l(appStub, gotResult);
    },
    toolResultCount: () => toolResultListeners.size,
    connectCount: () => connectListeners.size,
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

  it("fans onConnect out to every subscriber in the tree", () => {
    const { ctx, triggerConnect } = buildTestContext({ appStub: stubApp });

    const a = vi.fn();
    const b = vi.fn();

    function Probe({ cb }: { cb: OnConnect }) {
      useMcpAppEvents({ onConnect: cb });
      return null;
    }

    render(
      <Wrapper value={ctx}>
        <Probe cb={a} />
        <Probe cb={b} />
      </Wrapper>,
    );

    act(() => {
      triggerConnect(true);
    });

    expect(a).toHaveBeenCalledWith(stubApp, true);
    expect(b).toHaveBeenCalledWith(stubApp, true);
  });

  it("replays the cached connect firing into late subscribers", () => {
    // Provider already fired connect — context exposes this via the
    // replay hook. A subscriber that mounts now should be notified
    // synchronously.
    const { ctx } = buildTestContext({
      appStub: stubApp,
      replayConnect: { gotResult: false },
    });

    const late = vi.fn();

    function LateProbe() {
      useMcpAppEvents({ onConnect: late });
      return null;
    }

    render(
      <Wrapper value={ctx}>
        <LateProbe />
      </Wrapper>,
    );

    expect(late).toHaveBeenCalledTimes(1);
    expect(late).toHaveBeenCalledWith(stubApp, false);
  });

  it("uses the latest callback identity without re-subscribing on every render", () => {
    const { ctx, triggerToolResult, toolResultCount } = buildTestContext({
      appStub: stubApp,
    });

    const calls: number[] = [];

    function Probe() {
      const [n, setN] = useState(0);
      // Inline closure — identity changes every render. The hook
      // should stash the latest in a ref and keep a single underlying
      // subscription.
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

    // Still a single underlying subscription — the hook didn't churn
    // the provider's listener set.
    expect(toolResultCount()).toBe(1);
    expect(calls).toEqual([0, 1]);
  });

  it("unsubscribes on unmount", () => {
    const { ctx, toolResultCount, connectCount } = buildTestContext({
      appStub: stubApp,
    });

    function Probe() {
      useMcpAppEvents({ onToolResult: () => {}, onConnect: () => {} });
      return null;
    }

    const { unmount } = render(
      <Wrapper value={ctx}>
        <Probe />
      </Wrapper>,
    );

    expect(toolResultCount()).toBe(1);
    expect(connectCount()).toBe(1);

    unmount();

    expect(toolResultCount()).toBe(0);
    expect(connectCount()).toBe(0);
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

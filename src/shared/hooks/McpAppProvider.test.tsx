/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useEffect } from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import type { ToolResultParams } from "./McpAppContext.js";
import { McpAppProvider } from "./McpAppProvider.js";
import { useMcpApp } from "./useMcpApp.js";
import { useSpaces, type McpSpaceContextValue } from "./useSpaces.js";
import { createMcpAppBootstrap } from "../mcp-app-bootstrap.js";

type ToolParams = { name: string; arguments?: Record<string, unknown> };

const fake = vi.hoisted(() => {
  type Params = { name: string; arguments?: Record<string, unknown> };
  class FakeApp {
    /** What the transport would receive, after the provider's wrapper. */
    sent = vi.fn(async (params: Params) => fake.respond(params));
    updateModelContext = vi.fn(async () => ({}));
    connect = vi.fn(async () => {});
    close = vi.fn();
    ontoolresult?: (params: unknown) => void;
    onhostcontextchanged?: (params: unknown) => void;
    callServerTool(params: Params, _options?: unknown) {
      return this.sent(params);
    }
    constructor() {
      fake.instances.push(this);
    }
  }
  return {
    FakeApp,
    instances: [] as InstanceType<typeof FakeApp>[],
    respond: (_params: Params): unknown => ({ content: [] }),
  };
});

vi.mock("@modelcontextprotocol/ext-apps", () => ({ App: fake.FakeApp }));

const LIST = {
  configured: "default",
  spaces: [
    { id: "default", name: "Default" },
    { id: "soc", name: "SOC" },
  ],
};

function jsonResult(data: unknown) {
  return { content: [{ type: "text", text: JSON.stringify(data) }] };
}

function bootstrapPush(): ToolResultParams {
  const envelope = createMcpAppBootstrap("alert-triage", {
    summary: { total: 0, bySeverity: {}, byRule: [], byHost: [], alerts: [] },
    params: { days: 7, limit: 50 },
    verdicts: [],
  });
  return jsonResult(envelope) as unknown as ToolResultParams;
}

function sentCalls(name?: string): ToolParams[] {
  const app = fake.instances[fake.instances.length - 1];
  return app.sent.mock.calls
    .map((call) => call[0] as ToolParams)
    .filter((params) => !name || params.name === name);
}

let spaces: McpSpaceContextValue;
let mounts = 0;

function Probe() {
  const { connected, getApp, bootstrapState } = useMcpApp();
  spaces = useSpaces();
  useEffect(() => {
    mounts += 1;
  }, []);
  useEffect(() => {
    if (!connected || bootstrapState.status !== "idle") return;
    void getApp()?.callServerTool({ name: "poll-alerts", arguments: { days: 7 } });
  }, [connected, bootstrapState.status, getApp]);
  return (
    <div>
      <span data-testid="active">{spaces.active}</span>
      <span data-testid="bootstrap">{bootstrapState.status}</span>
    </div>
  );
}

function renderProvider() {
  return render(
    <McpAppProvider name="alert-triage" version="1.0.0">
      <Probe />
    </McpAppProvider>,
  );
}

beforeEach(() => {
  fake.instances.length = 0;
  mounts = 0;
  fake.respond = (params) => (params.name === "list-spaces" ? jsonResult(LIST) : { content: [] });
});

describe("McpAppProvider — Kibana spaces", () => {
  it("loads list-spaces once after connecting", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    expect(spaces.configured).toBe("default");
    expect(spaces.active).toBe("default");
    expect(sentCalls("list-spaces")).toEqual([{ name: "list-spaces", arguments: {} }]);
  });

  it("keeps spaces empty when list-spaces fails", async () => {
    fake.respond = (params) => {
      if (params.name === "list-spaces") throw new Error("unknown tool");
      return { content: [] };
    };
    renderProvider();
    await waitFor(() => expect(sentCalls("list-spaces")).toHaveLength(1));
    await act(async () => {});
    expect(spaces.spaces).toEqual([]);
    expect(spaces.configured).toBe("");
  });

  it("does not add space to calls while the configured space is active", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    expect(sentCalls("poll-alerts")).toEqual([{ name: "poll-alerts", arguments: { days: 7 } }]);
  });

  it("on switch, tells the model, remounts the view and scopes later calls", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    const app = fake.instances[0];
    expect(mounts).toBe(1);

    await act(async () => {
      await spaces.setActiveSpace("soc");
    });

    expect(app.updateModelContext).toHaveBeenCalledTimes(1);
    const [params] = app.updateModelContext.mock.calls[0] as unknown as [
      { content: Array<{ type: string; text: string }> },
    ];
    expect(params.content).toHaveLength(1);
    expect(params.content[0].type).toBe("text");
    expect(params.content[0].text).toContain('switched the Elastic Security view to the Kibana space "SOC" (id: soc)');
    expect(params.content[0].text).toContain("follow-up questions");

    expect(screen.getByTestId("active")).toHaveTextContent("soc");
    expect(mounts).toBe(2);
    await waitFor(() => expect(sentCalls("poll-alerts")).toHaveLength(2));
    expect(sentCalls("poll-alerts")[1]).toEqual({
      name: "poll-alerts",
      arguments: { days: 7, space: "soc" },
    });

    await act(async () => {
      await app.callServerTool({ name: "report-analytics-event", arguments: { eventType: "x" } });
      await app.callServerTool({ name: "count-by-space", arguments: { kind: "alerts" } });
      await app.callServerTool({ name: "poll-cases", arguments: { space: "default" } });
    });
    expect(sentCalls("report-analytics-event")).toEqual([
      { name: "report-analytics-event", arguments: { eventType: "x" } },
    ]);
    expect(sentCalls("count-by-space")).toEqual([
      { name: "count-by-space", arguments: { kind: "alerts" } },
    ]);
    expect(sentCalls("poll-cases")).toEqual([
      { name: "poll-cases", arguments: { space: "default" } },
    ]);
  });

  it("resets a ready bootstrap to idle so the remounted view self-loads", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    const app = fake.instances[0];

    act(() => {
      app.ontoolresult?.(bootstrapPush());
    });
    expect(screen.getByTestId("bootstrap")).toHaveTextContent("ready");

    await act(async () => {
      await spaces.setActiveSpace("soc");
    });
    expect(screen.getByTestId("bootstrap")).toHaveTextContent("idle");
    await waitFor(() =>
      expect(sentCalls("poll-alerts").at(-1)).toEqual({
        name: "poll-alerts",
        arguments: { days: 7, space: "soc" },
      }),
    );

    // A late bootstrap describes the previous space, so it must not land.
    act(() => {
      app.ontoolresult?.(bootstrapPush());
    });
    expect(screen.getByTestId("bootstrap")).toHaveTextContent("idle");
  });

  it("switches back to the configured space without a space argument", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    const app = fake.instances[0];

    await act(async () => {
      await spaces.setActiveSpace("soc");
    });
    await act(async () => {
      await spaces.setActiveSpace("default");
    });

    const texts = app.updateModelContext.mock.calls.map(
      (call) => (call as unknown as [{ content: Array<{ text: string }> }])[0].content[0].text,
    );
    expect(texts[1]).toContain('back to their configured Kibana space "Default" (id: default)');
    expect(screen.getByTestId("active")).toHaveTextContent("default");
    await waitFor(() => expect(sentCalls("poll-alerts")).toHaveLength(3));
    expect(sentCalls("poll-alerts")[2]).toEqual({ name: "poll-alerts", arguments: { days: 7 } });
  });

  it("is a no-op when the space is already active", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    await act(async () => {
      await spaces.setActiveSpace("default");
    });
    expect(fake.instances[0].updateModelContext).not.toHaveBeenCalled();
    expect(mounts).toBe(1);
  });

  it("still switches when the host rejects the model context update", async () => {
    renderProvider();
    await waitFor(() => expect(spaces.spaces).toHaveLength(2));
    fake.instances[0].updateModelContext.mockRejectedValueOnce(new Error("unsupported"));
    await act(async () => {
      await spaces.setActiveSpace("soc");
    });
    expect(screen.getByTestId("active")).toHaveTextContent("soc");
    expect(mounts).toBe(2);
  });
});

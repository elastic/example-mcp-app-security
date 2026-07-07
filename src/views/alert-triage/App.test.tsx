/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, waitFor, act } from "@testing-library/react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { McpAppContext, type McpAppContextValue } from "../../shared/hooks/McpAppContext.js";
import { ToastProvider } from "../../shared/components/index.js";
import { AppContent } from "./App.js";
import type { AlertSummary, SecurityAlert } from "../../shared/types.js";

/** Mirrors the real `App`'s wrapping (`ToastProvider` + `McpAppProvider`),
 * swapping the real provider/transport for a stubbed context. */
function renderAppContent(ctx: McpAppContextValue) {
  return render(
    <ToastProvider>
      <McpAppContext.Provider value={ctx}>
        <AppContent />
      </McpAppContext.Provider>
    </ToastProvider>
  );
}

interface FakeApp {
  callServerTool: ReturnType<typeof vi.fn>;
}

function makeContext(app: FakeApp): McpAppContextValue {
  return {
    app: app as unknown as McpApp,
    getApp: () => app as unknown as McpApp,
    connected: true,
    bootstrapState: { status: "idle" },
    subscribeToToolResult: () => () => {},
  };
}

function makeAlert(id: string, host: string): SecurityAlert {
  return {
    _id: id,
    _index: ".alerts-security.alerts-default",
    _source: {
      "@timestamp": "2024-01-01T00:00:00Z",
      "kibana.alert.rule.name": "R",
      "kibana.alert.rule.uuid": "r",
      "kibana.alert.severity": "high",
      "kibana.alert.risk_score": 73,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "x",
      host: { name: host },
    },
  };
}

function unfilteredSummary(): AlertSummary {
  return {
    total: 2,
    bySeverity: { high: 2 },
    byRule: [{ name: "R", count: 2 }],
    byHost: [
      { name: "host-a", count: 1 },
      { name: "host-b", count: 1 },
    ],
    alerts: [makeAlert("a1", "host-a"), makeAlert("a2", "host-b")],
  };
}

function filteredSummary(host: string): AlertSummary {
  return {
    total: 1,
    bySeverity: { high: 1 },
    byRule: [{ name: "R", count: 1 }],
    byHost: [{ name: host, count: 1 }],
    alerts: [makeAlert("f1", host)],
  };
}

function toolResult(summary: AlertSummary) {
  return { content: [{ type: "text", text: JSON.stringify(summary) }] };
}

function pollAlertsCalls(callServerTool: ReturnType<typeof vi.fn>) {
  return callServerTool.mock.calls.filter((call) => call[0]?.name === "poll-alerts");
}

describe("Alert Triage AppContent — filter clearing", () => {
  it("clears the filter and reloads the unfiltered list when the input is emptied directly, not via Enter/Escape/the chip", async () => {
    const callServerTool = vi.fn().mockImplementation(async ({ name, arguments: args }) => {
      if (name !== "poll-alerts") return toolResult(unfilteredSummary());
      return toolResult(args?.query ? filteredSummary("host-x") : unfilteredSummary());
    });
    const ctx = makeContext({ callServerTool });

    const { getByLabelText, queryByLabelText } = renderAppContent(ctx);

    // Initial unfiltered load on mount.
    await waitFor(() => expect(pollAlertsCalls(callServerTool).length).toBeGreaterThan(0));

    const input = getByLabelText("Filter") as HTMLInputElement;

    // Apply a filter the normal way: type + Enter.
    fireEvent.change(input, { target: { value: "host-x" } });
    fireEvent.keyDown(input, { key: "Enter" });

    await waitFor(() => expect(queryByLabelText("Clear filter")).toBeTruthy());
    const afterFilter = pollAlertsCalls(callServerTool);
    expect(afterFilter[afterFilter.length - 1][0].arguments.query).toBe("host-x");

    // Regression: clear by deleting the input's text directly — no Enter,
    // no Escape, no click on the chip's "x". Before the fix, this only
    // updated local text state and never re-queried, leaving the widget
    // filtered on "host-x" even though the box (and, per the bug report,
    // the chip) looked empty.
    fireEvent.change(input, { target: { value: "" } });

    await waitFor(() => {
      const afterClear = pollAlertsCalls(callServerTool);
      expect(afterClear[afterClear.length - 1][0].arguments.query).toBeUndefined();
    });

    // The chip is driven by the same underlying filter state, so it should
    // be gone too — proving the filter was actually cleared, not just the
    // text box.
    await waitFor(() => expect(queryByLabelText("Clear filter")).toBeNull());
  });

  it("does not re-fire a reload when the input is already empty and no filter is active", async () => {
    const callServerTool = vi.fn().mockResolvedValue(toolResult(unfilteredSummary()));
    const ctx = makeContext({ callServerTool });

    const { getByLabelText } = renderAppContent(ctx);

    await waitFor(() => expect(pollAlertsCalls(callServerTool).length).toBeGreaterThan(0));
    const countAfterMount = pollAlertsCalls(callServerTool).length;

    const input = getByLabelText("Filter") as HTMLInputElement;
    // Typing and then deleting back to empty without ever having an active
    // filter should not trigger an extra reload.
    fireEvent.change(input, { target: { value: "h" } });
    fireEvent.change(input, { target: { value: "" } });

    expect(pollAlertsCalls(callServerTool).length).toBe(countAfterMount);
  });
});

describe("Alert Triage AppContent — stale response guard", () => {
  it("does not let an older, slower response overwrite a newer one that resolved first", async () => {
    const deferred: Array<() => void> = [];
    let pollCallIndex = 0;

    const callServerTool = vi.fn().mockImplementation(async ({ name, arguments: args }) => {
      if (name !== "poll-alerts") return toolResult(unfilteredSummary());
      const idx = pollCallIndex++;
      if (idx === 0) {
        // Initial mount load — resolve immediately.
        return toolResult(unfilteredSummary());
      }
      return new Promise((resolve) => {
        deferred[idx] = () =>
          resolve(toolResult(args?.query ? filteredSummary("host-old") : unfilteredSummary()));
      });
    });
    const ctx = makeContext({ callServerTool });

    const { getByLabelText, queryByText, getAllByText } = renderAppContent(ctx);

    await waitFor(() => expect(pollCallIndex).toBe(1));

    const input = getByLabelText("Filter") as HTMLInputElement;

    // Request #1 (older): apply a filter — its response will be resolved LAST.
    fireEvent.change(input, { target: { value: "host-old" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(pollCallIndex).toBe(2));

    // Request #2 (newer): clear it via the chip — its response will be
    // resolved FIRST, simulating the older request's network round-trip
    // taking longer than the newer one's.
    fireEvent.click(getByLabelText("Clear filter"));
    await waitFor(() => expect(pollCallIndex).toBe(3));

    // Resolve out of order: newer (#2, unfiltered) first, older (#1, filtered) second.
    await act(async () => deferred[2]());
    await act(async () => deferred[1]());

    // The stale filtered response must have been discarded — the list
    // should reflect the newer, unfiltered result, not "host-old".
    expect(queryByText("host-old")).toBeNull();
    expect(getAllByText("host-a").length).toBeGreaterThan(0);
  });
});

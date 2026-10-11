/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, waitFor, within } from "@testing-library/react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { McpAppContext, type McpAppContextValue } from "../../shared/hooks/McpAppContext.js";
import type { McpAppBootstrapState } from "../../shared/mcp-app-bootstrap.js";
import { createMcpAppBootstrap } from "../../shared/mcp-app-bootstrap.js";
import { ToastProvider } from "../../shared/components/index.js";
import type {
  AlertZeroAvailabilityState,
  AlertZeroListResult,
  AlertZeroProposalCard,
  AlertZeroStatus,
} from "../../shared/alert-zero-types.js";
import type { ProposalDetailProps } from "./types.js";
import { AppContent } from "./App.js";
import { UNAVAILABLE_TITLE, UnavailablePanel } from "./components/list/UnavailablePanel.js";

vi.mock("./components/detail/ProposalDetail", () => ({
  ProposalDetail: ({ card, reloadToken, onSelectProposal }: ProposalDetailProps) => (
    <div data-testid="proposal-detail">
      <span>detail:{card.title}</span>
      <span>reload:{reloadToken}</span>
      <button
        type="button"
        onClick={() => onSelectProposal?.({ ...card, id: "sibling-1", title: "Sibling proposal" })}
      >
        open sibling
      </button>
    </div>
  ),
}));

const LIST_TOOL = "list-alert-zero-proposals";
const KIBANA_URL = "https://kb.example.com";

interface FakeApp {
  callServerTool: ReturnType<typeof vi.fn>;
  openLink: ReturnType<typeof vi.fn>;
}

function makeApp(listImpl: (args: Record<string, unknown>) => unknown): FakeApp {
  return {
    callServerTool: vi.fn().mockImplementation(async ({ name, arguments: args }) => {
      if (name !== LIST_TOOL) return { content: [] };
      return listImpl(args ?? {});
    }),
    openLink: vi.fn().mockResolvedValue({}),
  };
}

function makeContext(app: FakeApp, bootstrapState: McpAppBootstrapState = { status: "idle" }): McpAppContextValue {
  return {
    app: app as unknown as McpApp,
    getApp: () => app as unknown as McpApp,
    connected: true,
    bootstrapState,
    subscribeToToolResult: () => () => {},
  };
}

function renderAppContent(ctx: McpAppContextValue) {
  return render(
    <ToastProvider>
      <McpAppContext.Provider value={ctx}>
        <AppContent />
      </McpAppContext.Provider>
    </ToastProvider>,
  );
}

function listCalls(app: FakeApp): Record<string, unknown>[] {
  return app.callServerTool.mock.calls
    .filter((call) => call[0]?.name === LIST_TOOL)
    .map((call) => call[0].arguments as Record<string, unknown>);
}

function sectionLabels(container: HTMLElement): (string | null)[] {
  return [...container.querySelectorAll("section.az-section")].map((s) => s.getAttribute("aria-label"));
}

function card(overrides: Partial<AlertZeroProposalCard> & { id: string }): AlertZeroProposalCard {
  return {
    conversationId: "conv-1",
    title: `Proposal ${overrides.id}`,
    status: "pending",
    impact: "medium",
    confidence: "high",
    createdAt: new Date(Date.now() - 3_600_000).toISOString(),
    hasPreviousExecutionError: false,
    assignees: [],
    assignedToMe: false,
    priorityScore: 50,
    commentExcerpt: "",
    targets: [],
    ...overrides,
  };
}

const ENABLED: AlertZeroStatus = {
  state: "enabled",
  available: true,
  spaceId: "soc",
  reason: "Alert Zero is enabled",
  canRead: true,
  canDecide: true,
};

function listResult(overrides: Partial<AlertZeroListResult> = {}): AlertZeroListResult {
  const proposals = overrides.proposals ?? [
    card({ id: "p1", category: "respond", investigationTitle: "Ransomware on host-7", actionName: "Isolate host", impact: "critical" }),
    card({ id: "p2", category: "configure", conversationId: "conv-2", investigationTitle: "Noisy rule" }),
  ];
  return {
    status: ENABLED,
    spaceId: "soc",
    kibanaUrl: KIBANA_URL,
    scope: "all",
    category: "all",
    totalAwaitingDecision: proposals.length,
    countsByCategory: { respond: 1, investigate: 0, configure: 1 },
    truncated: false,
    ...overrides,
    proposals,
  };
}

function toolResult(value: unknown) {
  return { content: [{ type: "text", text: JSON.stringify(value) }] };
}

function unavailable(state: AlertZeroAvailabilityState): AlertZeroListResult {
  return listResult({
    status: {
      state,
      available: false,
      spaceId: "soc",
      reason: "Alert Zero is turned off in space soc.",
      remediation: "Enable securitySolution:enableAlertZero in Advanced Settings.",
      canRead: false,
      canDecide: false,
    },
    proposals: [],
    totalAwaitingDecision: 0,
    countsByCategory: { respond: 0, investigate: 0, configure: 0 },
  });
}

describe("Alert Zero AppContent — bootstrap", () => {
  it("hydrates from the bootstrap payload without self-loading and groups by category", async () => {
    const app = makeApp(() => toolResult(listResult()));
    const payload = listResult({
      spaceId: "default",
      proposals: [
        card({ id: "p1", category: "respond", investigationTitle: "Ransomware on host-7" }),
        card({ id: "p2", category: "configure", conversationId: "conv-2" }),
        card({ id: "p3", category: "something-new", investigationTitle: "Ransomware on host-7" }),
      ],
    });
    const ctx = makeContext(app, { status: "ready", envelope: createMcpAppBootstrap("alert-zero", payload) });

    const { container, getByText, queryByText, getByRole } = renderAppContent(ctx);

    expect(getByText("3 actions need you")).toBeTruthy();
    expect(queryByText(/^Space:/)).toBeNull();
    expect(sectionLabels(container)).toEqual(["Respond, 1 proposal", "Configure, 1 proposal", "Other, 1 proposal"]);

    fireEvent.click(within(getByRole("group", { name: "Group by" })).getByRole("button", { name: "Investigation" }));
    expect(sectionLabels(container)).toEqual(["Ransomware on host-7, 2 proposals", "Untitled investigation, 1 proposal"]);

    await waitFor(() =>
      expect(app.callServerTool.mock.calls.filter((c) => c[0]?.name === "report-analytics-event")).toHaveLength(1),
    );
    expect(listCalls(app)).toHaveLength(0);
  });
});

describe("Alert Zero AppContent — unavailable state", () => {
  it("explains a space-level disable and wires Check again + Advanced Settings", async () => {
    const app = makeApp(() => toolResult(unavailable("disabled_in_space")));
    const { findByText, getByText, getByRole, queryByRole } = renderAppContent(makeContext(app));

    expect(await findByText("Alert Zero is off in this space")).toBeTruthy();
    expect(getByText("Alert Zero is turned off in space soc.")).toBeTruthy();
    expect(getByText("Enable securitySolution:enableAlertZero in Advanced Settings.")).toBeTruthy();
    expect(getByText("soc")).toBeTruthy();
    expect(getByText("Space: soc")).toBeTruthy();
    expect(queryByRole("group", { name: "Assignment" })).toBeNull();

    fireEvent.click(getByRole("button", { name: "Open Advanced Settings" }));
    expect(app.openLink).toHaveBeenCalledWith({
      url: `${KIBANA_URL}/s/soc/app/management/kibana/settings?query=enableAlertZero`,
    });

    fireEvent.click(getByRole("button", { name: "Check again" }));
    await waitFor(() => expect(listCalls(app)).toHaveLength(2));
    expect(listCalls(app)[1]).toEqual({ scope: "all", category: "all", spaceId: "soc" });
  });

  it.each(Object.entries(UNAVAILABLE_TITLE).filter(([state]) => state !== "enabled"))(
    "titles the %s state",
    (state, title) => {
      const status = unavailable(state as AlertZeroAvailabilityState).status;
      const { getByRole, queryByRole } = render(
        <UnavailablePanel
          status={status}
          spaceId="default"
          kibanaUrl={KIBANA_URL}
          checking={false}
          onCheckAgain={() => {}}
          onOpenLink={() => {}}
        />,
      );
      expect(getByRole("heading", { name: title })).toBeTruthy();
      expect(getByRole("button", { name: "Check again" })).toBeTruthy();
      expect(queryByRole("button", { name: "Open Advanced Settings" }) !== null).toBe(state === "disabled_in_space");
    },
  );
});

describe("Alert Zero AppContent — filters", () => {
  it("self-loads when there is no bootstrap, then sends scope/category/spaceId on each pill change", async () => {
    const app = makeApp((args) =>
      toolResult(
        listResult({
          scope: (args.scope as AlertZeroListResult["scope"]) ?? "all",
          category: (args.category as AlertZeroListResult["category"]) ?? "all",
        }),
      ),
    );
    const { getByRole, findByText } = renderAppContent(makeContext(app));

    await findByText("2 actions need you");
    expect(listCalls(app)).toEqual([{ scope: "all", category: "all", spaceId: undefined }]);

    const assignment = getByRole("group", { name: "Assignment" });
    fireEvent.click(within(assignment).getByRole("button", { name: "Assigned to me" }));
    await waitFor(() => expect(listCalls(app)).toHaveLength(2));
    expect(listCalls(app)[1]).toEqual({ scope: "mine", category: "all", spaceId: "soc" });
    await waitFor(() =>
      expect(within(assignment).getByRole("button", { name: "Assigned to me" }).getAttribute("aria-pressed")).toBe("true"),
    );

    const categories = getByRole("group", { name: "Category" });
    fireEvent.click(within(categories).getByRole("button", { name: /Respond/ }));
    await waitFor(() => expect(listCalls(app)).toHaveLength(3));
    expect(listCalls(app)[2]).toEqual({ scope: "mine", category: "respond", spaceId: "soc" });
  });

  it("toasts on failure and restores the last successful filter", async () => {
    let fail = false;
    const app = makeApp(() =>
      fail ? { isError: true, content: [{ type: "text", text: "Kibana returned 500" }] } : toolResult(listResult()),
    );
    const { getByRole, findByText } = renderAppContent(makeContext(app));
    await findByText("2 actions need you");

    fail = true;
    const assignment = getByRole("group", { name: "Assignment" });
    fireEvent.click(within(assignment).getByRole("button", { name: "Unassigned" }));

    expect(await findByText("Couldn't load Alert Zero proposals: Kibana returned 500")).toBeTruthy();
    expect(within(assignment).getByRole("button", { name: "All" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("distinguishes an empty queue from an empty filter", async () => {
    const empty = { proposals: [], totalAwaitingDecision: 0, countsByCategory: { respond: 0, investigate: 0, configure: 0 } };
    const app = makeApp((args) => toolResult(listResult({ ...empty, scope: (args.scope as AlertZeroListResult["scope"]) ?? "all" })));
    const { findByText, getByRole } = renderAppContent(makeContext(app));

    expect(await findByText("Nothing awaiting your decision")).toBeTruthy();
    expect(await findByText("You're all caught up")).toBeTruthy();

    fireEvent.click(within(getByRole("group", { name: "Assignment" })).getByRole("button", { name: "Unassigned" }));
    expect(await findByText("No proposals match this filter")).toBeTruthy();
  });
});

describe("Alert Zero AppContent — detail selection", () => {
  it("opens the detail for a card, keeps it in sync, and keeps it open after it leaves the list", async () => {
    let version = 0;
    const app = makeApp(() => {
      const p1 = card({ id: "p1", category: "respond", title: version === 0 ? "Isolate host-7" : "Isolate host-7 (rev 2)", revision: version === 0 ? 1 : 2 });
      const p2 = card({ id: "p2", category: "configure" });
      return toolResult(listResult({ proposals: version < 2 ? [p1, p2] : [p2] }));
    });
    const { findByRole, getByRole, getByTestId, queryByTestId, getByText } = renderAppContent(makeContext(app));

    fireEvent.click(await findByRole("button", { name: /Isolate host-7/ }));
    expect(getByText("detail:Isolate host-7")).toBeTruthy();
    expect(getByText("reload:0")).toBeTruthy();
    expect(getByRole("button", { name: /Isolate host-7/ }).getAttribute("aria-pressed")).toBe("true");

    version = 1;
    fireEvent.click(getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(getByText("detail:Isolate host-7 (rev 2)")).toBeTruthy());
    expect(getByText("reload:1")).toBeTruthy();
    expect(getByText("Rev 2")).toBeTruthy();

    version = 2;
    fireEvent.click(getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(getByText("reload:2")).toBeTruthy());
    expect(getByText("detail:Isolate host-7 (rev 2)")).toBeTruthy();
    expect(queryByTestId("proposal-detail")).not.toBeNull();

    fireEvent.click(getByRole("button", { name: /Proposal p2/ }));
    fireEvent.click(within(getByTestId("proposal-detail")).getByRole("button", { name: "open sibling" }));
    expect(getByText("detail:Sibling proposal")).toBeTruthy();

    fireEvent.click(getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(listCalls(app)).toHaveLength(4));
    await waitFor(() => expect(getByText("reload:3")).toBeTruthy());
    expect(getByText("detail:Sibling proposal")).toBeTruthy();
  });
});

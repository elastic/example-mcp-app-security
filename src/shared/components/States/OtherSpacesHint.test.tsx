/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { McpAppContext, type McpAppContextValue } from "../../hooks/McpAppContext.js";
import { McpSpaceContext, type McpSpaceContextValue } from "../../hooks/McpSpaceContext.js";
import type { SpaceCountKind, SpaceSummary } from "../../spaces.js";
import { OtherSpacesHint } from "./OtherSpacesHint.js";

const SPACES: SpaceSummary[] = [
  { id: "default", name: "Default" },
  { id: "soc", name: "SOC" },
  { id: "dev", name: "Dev" },
  { id: "empty", name: "Empty" },
];

function countsResult(kind: SpaceCountKind, counts: Record<string, number>) {
  return { content: [{ type: "text", text: JSON.stringify({ kind, days: 7, counts }) }] };
}

function renderHint({
  callServerTool,
  spaces = SPACES,
  active = "default",
  kind = "alerts",
  days,
}: {
  callServerTool: ReturnType<typeof vi.fn>;
  spaces?: SpaceSummary[];
  active?: string;
  kind?: SpaceCountKind;
  days?: number;
}) {
  const app = { callServerTool } as unknown as McpApp;
  const appCtx: McpAppContextValue = {
    app,
    getApp: () => app,
    connected: true,
    bootstrapState: { status: "idle" },
    subscribeToToolResult: () => () => {},
  };
  const spaceCtx: McpSpaceContextValue = {
    configured: "default",
    active,
    spaces,
    setActiveSpace: vi.fn().mockResolvedValue(undefined),
  };
  const view = render(
    <McpAppContext.Provider value={appCtx}>
      <McpSpaceContext.Provider value={spaceCtx}>
        <OtherSpacesHint kind={kind} days={days} />
      </McpSpaceContext.Provider>
    </McpAppContext.Provider>,
  );
  return { ...view, spaceCtx };
}

describe("OtherSpacesHint", () => {
  it("lists other spaces with counts, largest first, excluding the active space and zeros", async () => {
    const callServerTool = vi
      .fn()
      .mockResolvedValue(countsResult("alerts", { default: 9, soc: 3, dev: 12, empty: 0 }));
    const { container } = renderHint({ callServerTool, days: 30 });

    await waitFor(() => expect(screen.getByText(/are in other spaces/)).toBeInTheDocument());
    expect(callServerTool).toHaveBeenCalledWith({
      name: "count-by-space",
      arguments: { kind: "alerts", days: 30 },
    });
    expect(container.querySelector(".other-spaces-hint-title")).toHaveTextContent(
      "Nothing here in Default, but 15 open alerts are in other spaces:",
    );
    const rows = screen.getAllByRole("button");
    expect(rows.map((r) => r.querySelector(".other-spaces-hint-name")?.textContent)).toEqual([
      "Dev",
      "SOC",
    ]);
    expect(rows[0]).toHaveTextContent("12");
    expect(rows[0]).toHaveTextContent("View →");
    expect(screen.getByText(/Click a space to view it for this session/)).toHaveTextContent(
      "Click a space to view it for this session. To change your default, set the Kibana space in your Elastic Security connection settings.",
    );
  });

  it("switches to the clicked space", async () => {
    const callServerTool = vi.fn().mockResolvedValue(countsResult("discoveries", { soc: 2 }));
    const { spaceCtx, container } = renderHint({ callServerTool, kind: "discoveries" });

    await waitFor(() => expect(screen.getByRole("button", { name: /SOC/ })).toBeInTheDocument());
    expect(container.querySelector(".other-spaces-hint-title")).toHaveTextContent(
      "Nothing here in Default, but 2 attack discoveries are in other spaces:",
    );
    fireEvent.click(screen.getByRole("button", { name: /SOC/ }));
    expect(spaceCtx.setActiveSpace).toHaveBeenCalledWith("soc");
  });

  it("omits days when the view has none", async () => {
    const callServerTool = vi.fn().mockResolvedValue(countsResult("alerts", { soc: 1 }));
    renderHint({ callServerTool });
    await waitFor(() => expect(screen.getByText(/is in another space/)).toBeInTheDocument());
    expect(callServerTool).toHaveBeenCalledWith({
      name: "count-by-space",
      arguments: { kind: "alerts" },
    });
    expect(screen.getByText(/1 open alert is in another space/)).toBeInTheDocument();
  });

  it("renders nothing when only the active space has matches", async () => {
    const callServerTool = vi.fn().mockResolvedValue(countsResult("alerts", { default: 4, soc: 0 }));
    const { container } = renderHint({ callServerTool });
    await waitFor(() => expect(callServerTool).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("leaves out spaces that list-spaces didn't return", async () => {
    const callServerTool = vi
      .fn()
      .mockResolvedValue(countsResult("alerts", { default: 0, soc: 3, "no-kibana-access": 9 }));
    renderHint({ callServerTool });
    expect(await screen.findByText(/3 open alerts are in other spaces/)).toBeInTheDocument();
    expect(screen.queryByText("no-kibana-access")).not.toBeInTheDocument();
  });

  it("skips the count call when fewer than two spaces are accessible", () => {
    const callServerTool = vi.fn();
    const { container } = renderHint({ callServerTool, spaces: [SPACES[0]] });
    expect(callServerTool).not.toHaveBeenCalled();
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the count call fails", async () => {
    const callServerTool = vi.fn().mockRejectedValue(new Error("unknown tool"));
    const { container } = renderHint({ callServerTool });
    await waitFor(() => expect(callServerTool).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });
});

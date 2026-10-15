/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, screen } from "@testing-library/react";
import { McpSpaceContext, type McpSpaceContextValue } from "../../hooks/McpSpaceContext.js";
import type { SpaceSummary } from "../../spaces.js";
import { AppHeader } from "./AppHeader.js";
import { SpaceControl } from "./SpaceControl.js";

const SPACES: SpaceSummary[] = [
  { id: "default", name: "Default", color: "#00bfb3", initials: "D" },
  { id: "soc-tier-2", name: "SOC Tier 2", color: "#1f2b5c" },
  { id: "dev", name: "Dev" },
];

function renderControl(overrides: Partial<McpSpaceContextValue> = {}) {
  const value: McpSpaceContextValue = {
    configured: "default",
    active: "default",
    spaces: SPACES,
    setActiveSpace: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
  render(
    <McpSpaceContext.Provider value={value}>
      <SpaceControl />
    </McpSpaceContext.Provider>,
  );
  return value;
}

describe("SpaceControl", () => {
  it("renders nothing without a space provider", () => {
    const { container } = render(<SpaceControl />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when only one space is accessible", () => {
    renderControl({ spaces: [SPACES[0]] });
    expect(screen.queryByRole("button", { name: /Kibana space/ })).toBeNull();
  });

  it("shows the active space with its avatar in a pill", () => {
    renderControl();
    const trigger = screen.getByRole("button", { name: "Kibana space: Default" });
    expect(trigger).toHaveTextContent("Space");
    expect(trigger).toHaveTextContent("Default");
    const avatar = trigger.querySelector(".app-header-space-avatar") as HTMLElement;
    expect(avatar).toHaveTextContent("D");
    expect(avatar.style.background).toBe("rgb(0, 191, 179)");
    expect(screen.queryByRole("button", { name: /Back to/ })).toBeNull();
  });

  it("derives initials when the space has none", () => {
    renderControl({ active: "soc-tier-2", configured: "soc-tier-2" });
    const avatar = screen
      .getByRole("button", { name: "Kibana space: SOC Tier 2" })
      .querySelector(".app-header-space-avatar") as HTMLElement;
    expect(avatar).toHaveTextContent("ST");
    expect(avatar.style.color).toBe("rgb(255, 255, 255)");
  });

  it("lists every space and switches to the one clicked", () => {
    const value = renderControl();
    fireEvent.click(screen.getByRole("button", { name: "Kibana space: Default" }));

    const options = screen.getAllByRole("option");
    expect(
      options.map((o) => o.querySelector(".app-header-space-option-name")?.textContent),
    ).toEqual(["Default", "SOC Tier 2", "Dev"]);
    expect(options[0]).toHaveAttribute("aria-selected", "true");

    fireEvent.click(options[1]);
    expect(value.setActiveSpace).toHaveBeenCalledWith("soc-tier-2");
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("closes the list on an outside click", () => {
    renderControl();
    fireEvent.click(screen.getByRole("button", { name: "Kibana space: Default" }));
    expect(screen.getByRole("listbox")).toBeInTheDocument();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("shows Viewing and a Back button while away from the configured space", () => {
    const value = renderControl({ active: "dev" });
    const trigger = screen.getByRole("button", { name: "Kibana space: Dev" });
    expect(trigger).toHaveTextContent("Viewing");
    expect(trigger).toHaveTextContent("Dev");

    fireEvent.click(screen.getByRole("button", { name: /Back to Default/ }));
    expect(value.setActiveSpace).toHaveBeenCalledWith("default");
  });

  it("renders right after the brand in AppHeader", () => {
    render(
      <McpSpaceContext.Provider
        value={{ configured: "default", active: "default", spaces: SPACES, setActiveSpace: vi.fn() }}
      >
        <AppHeader title="Alert Triage" leftExtras={<span data-testid="extras" />} />
      </McpSpaceContext.Provider>,
    );
    const left = document.querySelector(".app-header-left") as HTMLElement;
    const children = Array.from(left.children);
    expect(children[0]).toHaveClass("app-header-brand");
    expect(children[1]).toHaveClass("app-header-space");
    expect(children[2]).toBe(screen.getByTestId("extras"));
  });
});

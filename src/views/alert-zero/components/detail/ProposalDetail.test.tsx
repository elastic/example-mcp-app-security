/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, fireEvent, waitFor, within, screen } from "@testing-library/react";
import { PROPOSAL_FIELD_KEYS, toProposalCard } from "../../../../shared/alert-zero-types";
import type { AlertZeroApi } from "../../api";
import { ALERT_ZERO_APP_TOOLS } from "../../api";
import type { ProposalDetailProps } from "../../types";
import { coverageSections, type ProposalFieldKey } from "./fieldCoverage";
import { formatDateTime } from "./helpers";
import { ProposalDetail } from "./ProposalDetail";
import { FULL_PROPOSAL, SIBLING, makeDetail, makeInvestigation } from "./testFixtures";

function makeApi(opts: { investigationError?: string } = {}) {
  const callTool = vi.fn(async (name: string) => {
    if (name === ALERT_ZERO_APP_TOOLS.detail) return makeDetail();
    if (name === ALERT_ZERO_APP_TOOLS.investigation) {
      if (opts.investigationError) throw new Error(opts.investigationError);
      return makeInvestigation();
    }
    throw new Error(`unexpected tool ${name}`);
  });
  const api = {
    callTool,
    openLink: vi.fn(),
    sendMessage: vi.fn(),
    downloadFile: vi.fn(),
  };
  return api as typeof api & AlertZeroApi;
}

function renderDetail(api: AlertZeroApi, props: Partial<ProposalDetailProps> = {}) {
  return render(
    <ProposalDetail
      card={toProposalCard(FULL_PROPOSAL)}
      spaceId="soc-space"
      kibanaUrl="http://kibana.test"
      api={api}
      {...props}
    />,
  );
}

async function waitForLoaded(container: HTMLElement) {
  await waitFor(() => expect(container.querySelector('[data-section="Why"]')).toBeTruthy());
  await waitFor(() => expect(screen.getByRole("tab", { name: /Evidence/ }).textContent).toMatch(/\d/));
}

function openTab(name: RegExp) {
  fireEvent.click(screen.getByRole("tab", { name }));
}

/** Distinctive rendered text per field; per-section overrides where the display differs. */
const EXPECTED: Record<ProposalFieldKey, string | Record<string, string>> = {
  id: "prop-current-0002",
  spaceId: "soc-space",
  conversationId: "conv-1234",
  title: "Isolate host WIN-ANALYST01",
  comment: "Emotet and Qbot are running under jsmith",
  actionWorkflowId: "system-alertzero-action-isolate-host",
  actionInput: "agent-5cdcd6f1d75392d9",
  status: { Header: "Failed", Provenance: "failed" },
  decision: "Approved",
  supersededBy: "prop-next-0003",
  rootProposalId: "prop-root-0001",
  supersedes: "prop-root-0001",
  revision: "Revision 2 of 3",
  impact: "High impact",
  confidence: "Medium confidence",
  category: "Respond",
  origin: "alertzero",
  expiresAt: formatDateTime(FULL_PROPOSAL.expiresAt),
  decidedBy: "Dana Analyst",
  decidedAt: formatDateTime(FULL_PROPOSAL.decidedAt),
  dismissReason: "False positive",
  rationale: "approved after reviewing the Fleet status",
  executionError: "Endpoint agent offline",
  previousExecutionError: "Timeout contacting Fleet server",
  workflowExecutionId: "wf-exec-7777",
  createdAt: formatDateTime(FULL_PROPOSAL.createdAt),
  createdBy: "Worker Service",
  action: "Isolates Elastic Defend endpoints from the network.",
  conversationTitle: "Phishing to Emotet/Qbot Infection Chain",
  conversationAgentId: "elastic-ai-agent",
  conversationAssignees: "Riley Responder",
  entityIds: "host:host-win-analyst01",
};

describe("ProposalDetail — field coverage", () => {
  it("renders every proposal field inside each section FIELD_COVERAGE names", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    expect(Object.keys(EXPECTED).sort()).toEqual([...PROPOSAL_FIELD_KEYS].sort());

    const missing: string[] = [];
    for (const key of PROPOSAL_FIELD_KEYS) {
      for (const section of coverageSections(key)) {
        const expected = EXPECTED[key];
        const text = typeof expected === "string" ? expected : expected[section];
        const el = container.querySelector(`[data-section="${section}"]`);
        if (!text || !el?.textContent?.includes(text)) missing.push(`${key} → ${section} (${text})`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("calls detail and investigation in parallel with the card's ids", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    expect(api.callTool).toHaveBeenCalledWith(ALERT_ZERO_APP_TOOLS.detail, { proposalId: "prop-current-0002", spaceId: "soc-space" });
    expect(api.callTool).toHaveBeenCalledWith(ALERT_ZERO_APP_TOOLS.investigation, { conversationId: "conv-1234", spaceId: "soc-space" });
  });

  it("renders the header from the card before the detail call returns", () => {
    const api = makeApi();
    api.callTool.mockImplementation(() => new Promise(() => {}));
    const { container } = renderDetail(api);
    const header = container.querySelector('[data-section="Header"]');
    expect(header?.textContent).toContain("Isolate host WIN-ANALYST01");
    expect(header?.textContent).toContain("Phishing to Emotet/Qbot Infection Chain");
    expect(screen.getByText("Loading proposal…")).toBeInTheDocument();
  });

  it("shows the action card details and the exact input JSON", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    const what = container.querySelector('[data-section="What happens if you approve"]') as HTMLElement;
    expect(what.textContent).toContain("Network-isolate 2 endpoints");
    expect(what.textContent).toContain("agent-1a05df104769c426");
    expect(what.textContent).toContain("Contain WIN-ANALYST01 while remediation proceeds");
    expect(what.textContent).toContain("Affected hosts");
    expect(what.textContent).toContain("Approval depends on autonomy");
    fireEvent.click(within(what).getByRole("button", { name: /Exact input that will run/ }));
    expect(what.querySelector("pre")?.textContent).toContain('"endpoint_ids"');
  });

  it("navigates to siblings and revisions with a full card", async () => {
    const api = makeApi();
    const onSelectProposal = vi.fn();
    const { container } = renderDetail(api, { onSelectProposal });
    await waitForLoaded(container);
    fireEvent.click(screen.getByRole("button", { name: /Kill process regsvr32\.exe/ }));
    expect(onSelectProposal).toHaveBeenCalledTimes(1);
    const card = onSelectProposal.mock.calls[0][0];
    expect(card.id).toBe(SIBLING.id);
    expect(card.investigationTitle).toBe("Phishing to Emotet/Qbot Infection Chain");
    expect(card.assignees).toEqual([expect.objectContaining({ uid: "u_riley", fullName: "Riley Responder" })]);
  });
});

describe("ProposalDetail — agent activity", () => {
  it("merges events and rounds into one timeline without duplicating round replays", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    expect(screen.getByRole("tab", { name: /Agent activity/ }).textContent).toContain("8");
    openTab(/Agent activity/);

    const body = container.querySelector(".azd-body") as HTMLElement;
    for (const text of [
      "Excel phishing led to Emotet and Qbot on WIN-ANALYST01.",
      "Attack Discovery review covering 11 detection alerts.",
      "Handed off to Forensics Watch",
      "meta-extra-value",
      "wf-run-aaaa",
      "Riley Responder",
      'Review started for "Phishing to Emotet/Qbot Infection Chain".',
      "Proposed an action",
      "Agent run failed: Inference stream exceeded the maximum allowed duration",
      "Prompt answer text",
      "bar-future",
      "platform.core.execute_esql",
      "SRV-FILE",
      "ENOENT: no such file",
      "Here is the decision waiting on you.",
      "Approve it soon.",
      "80,476 in",
    ]) {
      expect(body.textContent, text).toContain(text);
    }
    expect(within(body).getAllByText("Worker").length).toBeGreaterThan(0);
    expect(within(body).getAllByText("What should I do next?")).toHaveLength(1);
    expect(body.querySelectorAll(".azd-prow.is-current").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(within(body).getByRole("button", { name: /Thinking/ }));
    expect(body.textContent).toContain("Let me pull the alerts first.");
    fireEvent.click(within(body).getByRole("button", { name: /Other result/ }));
    expect(body.textContent).toContain("other-result-payload");
    fireEvent.click(within(body).getByRole("button", { name: /Execution events/ }));
    expect(body.textContent).toContain("trace-round-1");
  });

  it("jumps from an attachment chip to the highlighted Evidence card", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    openTab(/Agent activity/);
    const chip = screen.getAllByRole("button", { name: /Added\s*Attack Discovery/ })[0];
    fireEvent.click(chip);
    expect(screen.getByRole("tab", { name: /Evidence/ })).toHaveAttribute("aria-selected", "true");
    await waitFor(() =>
      expect(container.querySelector('[data-attachment-id="attack-discovery"]')).toHaveClass("is-highlighted"),
    );
  });
});

describe("ProposalDetail — evidence", () => {
  it("renders every attachment type with its distinctive content", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    expect(screen.getByRole("tab", { name: /Evidence/ }).textContent).toContain("15");
    openTab(/Evidence/);
    const body = container.querySelector(".azd-body") as HTMLElement;

    for (const group of ["Proposals", "Attack", "Verdict", "Impact", "Alerts", "Timeline", "IOCs", "Hypotheses", "Rules", "Threat & signals", "Queries", "Notes", "Other"]) {
      expect(body.querySelector(`[data-group] h3`) && within(body).getAllByText(group).length, group).toBeTruthy();
    }
    const ad = body.querySelector('[data-attachment-id="attack-discovery"]') as HTMLElement;
    expect(ad.textContent).toContain("Infection on WIN-ANALYST01 as jsmith.");
    expect(ad.textContent).not.toContain("f2011eed");
    expect(ad.textContent).toContain("Initial Access");
    expect(ad.textContent).toContain("v1 of 1");
    expect(ad.textContent).toContain("Read-only");

    for (const text of [
      "Emotet Malware Detected",
      "alert-3",
      "jsmith@WIN-ANALYST01",
      "Hidden",
      "True positive",
      "This discovery holds up as a true positive.",
      "EXCEL.EXE spawns regsvr32.exe",
      "77.75.230.128",
      "C2 server, fetched 19825.dat",
      "Phishing macro dropper",
      "80% confidence",
      "EXCEL.EXE was the parent process",
      "Emotet Rule Name",
      "Qbot campaign report",
      'FROM logs-* | WHERE host.name == "WIN-ANALYST01"',
      "Analyst note: double-check backups",
      "mystery-value",
      "Second draft note",
      "Kill process regsvr32.exe",
    ]) {
      expect(body.textContent, text).toContain(text);
    }
    expect(body.textContent).not.toContain("Removed note content");
  });

  it("toggles removed attachments, switches versions, and downloads IOCs as CSV", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    openTab(/Evidence/);
    const body = container.querySelector(".azd-body") as HTMLElement;

    fireEvent.click(within(body).getByRole("switch", { name: /Show removed/ }));
    expect(body.textContent).toContain("Removed note content");
    expect(within(body).getAllByText("Removed").length).toBeGreaterThan(0);

    fireEvent.click(within(body).getByRole("button", { name: "v1" }));
    expect(body.textContent).toContain("First draft note");

    fireEvent.click(within(body).getByRole("button", { name: /Download CSV/ }));
    expect(api.downloadFile).toHaveBeenCalledWith(
      expect.objectContaining({
        mimeType: "text/csv",
        text: expect.stringContaining("ips,77.75.230.128,\"C2 server, fetched 19825.dat\""),
      }),
    );
    expect(api.downloadFile.mock.calls[0][0].text.startsWith("category,value,comment\n")).toBe(true);
  });
});

describe("ProposalDetail — all fields", () => {
  it("labels each field with its section and surfaces unknown server fields", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    openTab(/All fields/);
    const body = container.querySelector(".azd-body") as HTMLElement;
    expect(body.textContent).toContain("→ Why");
    expect(body.textContent).toContain("→ What happens if you approve");
    const other = within(body).getByText("Other fields").closest("section") as HTMLElement;
    expect(other.textContent).toContain("futureField");
    expect(other.textContent).toContain("from-the-future");
    for (const text of ["template_id", "investigation", "read_only", "access_control", "custom_meta", "canDecide"]) {
      expect(body.textContent, text).toContain(text);
    }
  });

  it("flags unknown fields from the Proposal tab", async () => {
    const api = makeApi();
    const { container } = renderDetail(api);
    await waitForLoaded(container);
    expect(container.querySelector('[data-section="Provenance"]')?.textContent).toContain("futureField");
  });
});

describe("ProposalDetail — failures and footer", () => {
  it("keeps the Proposal tab working when the investigation fails", async () => {
    const api = makeApi({ investigationError: "Conversation not found" });
    const { container } = renderDetail(api);
    await waitFor(() => expect(container.querySelector('[data-section="Why"]')).toBeTruthy());
    expect(container.querySelector('[data-section="Why"]')?.textContent).toContain("Emotet and Qbot");
    openTab(/Agent activity/);
    await waitFor(() => expect(screen.getByText("Couldn't load the investigation")).toBeInTheDocument());
    expect(screen.getByText("Conversation not found")).toBeInTheDocument();
  });

  it("renders the footer slot and link buttons", async () => {
    const api = makeApi();
    const renderFooterActions = vi.fn(() => <button type="button">Approve</button>);
    const { container } = renderDetail(api, { renderFooterActions });
    await waitForLoaded(container);
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    const [loaded, reload] = renderFooterActions.mock.calls.at(-1) as unknown as [
      { detail: { proposal: { id: string } }; investigation?: unknown },
      () => void,
    ];
    expect(loaded.detail.proposal.id).toBe("prop-current-0002");
    expect(loaded.investigation).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Open in Alert Zero/ }));
    expect(api.openLink).toHaveBeenCalledWith(makeDetail().links.alertZero);
    fireEvent.click(screen.getByRole("button", { name: /Open chat in Agent Builder/ }));
    expect(api.openLink).toHaveBeenCalledWith(makeDetail().links.agentBuilder);
    fireEvent.click(screen.getByRole("button", { name: /Ask Claude about this/ }));
    expect(api.sendMessage).toHaveBeenCalledWith(
      'Explain Alert Zero proposal prop-current-0002 ("Isolate host WIN-ANALYST01") using get-alert-zero-proposal, and tell me whether I should approve it.',
    );

    const calls = api.callTool.mock.calls.length;
    reload();
    await waitFor(() => expect(api.callTool.mock.calls.length).toBe(calls + 2));
  });
});

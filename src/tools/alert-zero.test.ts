/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { buildProposalDigest, registerAlertZeroTools, type ProposalDigest } from "./alert-zero.js";
import {
  createMockMcpServer,
  parseBootstrapToolText,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { createMockAlertZeroService } from "../test/helpers/mockServices.js";
import { noopAnalyticsClient } from "../test/helpers/mockAnalytics.js";
import { ALERT_ZERO_APP_TOOLS } from "../views/alert-zero/api.js";
import type {
  AlertZeroDecisionResult,
  AlertZeroInvestigation,
  AlertZeroListResult,
  AlertZeroProposalDetail,
  AlertZeroServiceApi,
  AlertZeroStatus,
  ProposalWithMetadata,
} from "../shared/alert-zero-types.js";

const RESOURCE_URI = "ui://review-alert-zero-proposals/mcp-app.html";
const KIBANA_URL = "https://kb.example.com";

const MODEL_TOOLS = [
  "review-alert-zero-proposals",
  "get-alert-zero-proposal",
  "check-alert-zero-status",
];
const APP_TOOLS = Object.values(ALERT_ZERO_APP_TOOLS);

function makeStatus(overrides: Partial<AlertZeroStatus> = {}): AlertZeroStatus {
  return {
    state: "enabled",
    available: true,
    spaceId: "default",
    reason: "Alert Zero is enabled",
    canRead: true,
    canDecide: true,
    ...overrides,
  };
}

function makeListResult(overrides: Partial<AlertZeroListResult> = {}): AlertZeroListResult {
  return {
    status: makeStatus(),
    spaceId: "default",
    kibanaUrl: KIBANA_URL,
    scope: "all",
    category: "all",
    totalAwaitingDecision: 1,
    countsByCategory: { respond: 1, investigate: 0, configure: 0 },
    proposals: [
      {
        id: "p-1",
        conversationId: "conv-1",
        title: "Isolate host-1",
        status: "pending",
        category: "respond",
        impact: "high",
        confidence: "high",
        createdAt: "2026-10-01T00:00:00Z",
        hasPreviousExecutionError: false,
        assignees: [],
        assignedToMe: false,
        priorityScore: 75,
        commentExcerpt: "Host shows ransomware behaviour",
        targets: ["1 endpoint"],
      },
    ],
    truncated: false,
    ...overrides,
  };
}

function makeProposal(overrides: Partial<ProposalWithMetadata> = {}): ProposalWithMetadata {
  return {
    id: "p-1",
    spaceId: "default",
    conversationId: "conv-1",
    title: "Isolate host-1",
    comment: "## Why\n" + "Evidence line. ".repeat(500),
    actionWorkflowId: "system-alertzero-action-isolate-host",
    actionInput: { endpoint_ids: ["ep-1"], comment: "x".repeat(5000) },
    status: "pending",
    impact: "high",
    confidence: "high",
    origin: "alertzero",
    rootProposalId: "p-0",
    revision: 2,
    createdAt: "2026-10-01T00:00:00Z",
    action: { name: "Isolate host", impact: "high", reversible: true, approvalPolicy: "always-gate" },
    ...overrides,
  };
}

function makeDetail(overrides: Partial<AlertZeroProposalDetail> = {}): AlertZeroProposalDetail {
  const proposal = makeProposal();
  return {
    proposal: { ...proposal, conversationTitle: "Ransomware on host-1", conversationAssignees: ["u-1"] },
    revisionChain: [
      makeProposal({
        id: "p-0",
        revision: 1,
        status: "superseded",
        decision: "dismissed",
        dismissReason: "other",
        decidedAt: "2026-09-30T00:00:00Z",
        decidedBy: { username: "alice", fullName: null, email: null },
      }),
      proposal,
    ],
    siblings: [makeProposal({ id: "p-9", title: "Close alerts", status: "failed", executionError: "boom" })],
    links: { alertZero: `${KIBANA_URL}/app/alertzero`, agentBuilder: `${KIBANA_URL}/app/agent_builder` },
    kibanaUrl: KIBANA_URL,
    spaceId: "default",
    canDecide: true,
    ...overrides,
  };
}

function makeInvestigation(): AlertZeroInvestigation {
  return {
    conversation: {
      id: "conv-1",
      agent_id: "alertzero-worker",
      title: "Ransomware on host-1",
      metadata: { status: "open", severity: "high", verdict: "malicious", summary: "s" },
      rounds: [
        {
          id: "r-1",
          status: "completed",
          started_at: "2026-10-01T00:00:00Z",
          input: { message: "i".repeat(4000) },
          response: { message: "r".repeat(8000) },
          steps: [
            { type: "reasoning", reasoning: "thinking" },
            {
              type: "tool_call",
              tool_call_id: "tc-1",
              tool_id: "security.alerts.search",
              params: { query: "q".repeat(2000) },
              results: [{ type: "esql_results", data: {} }, { type: "other", data: {} }],
            },
            { type: "reasoning", reasoning: "more" },
          ],
        },
      ],
      attachments: [
        {
          id: "att-1",
          type: "security.alerts",
          description: "Alerts",
          current_version: 2,
          active: true,
          origin: "alertzero",
          versions: [
            { version: 1, data: { old: true } },
            { version: 2, data: { alertIds: Array.from({ length: 500 }, (_, i) => `alert-${i}`) } },
          ],
        },
        {
          id: "att-2",
          type: "text",
          current_version: 1,
          active: false,
          versions: [{ version: 1, data: "short note" }],
        },
      ],
      events: [
        {
          id: "e-1",
          type: "user_message",
          created_at: "2026-10-01T00:00:00Z",
          actor: { type: "user", username: "alice" },
          data: { message: "m".repeat(5000) },
        },
        {
          id: "e-2",
          type: "attachment_added",
          created_at: "2026-10-01T00:01:00Z",
          actor: { type: "agent" },
          data: { attachment_id: "att-1", attachment_type: "security.alerts", current_version: 1 },
        },
        { id: "e-3", type: "execution_started", created_at: "2026-10-01T00:02:00Z", data: {} },
      ],
    },
    assignees: [{ uid: "u-1", username: "alice" }],
    alerts: { "alert-1": { id: "alert-1", ruleName: "Ransomware", severity: "high" } },
    links: { alertZero: `${KIBANA_URL}/app/alertzero`, agentBuilder: `${KIBANA_URL}/app/agent_builder` },
  };
}

describe("registerAlertZeroTools", () => {
  let server: MockMcpServer;
  let alertZeroService: AlertZeroServiceApi;

  beforeEach(() => {
    server = createMockMcpServer();
    alertZeroService = createMockAlertZeroService(KIBANA_URL);
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>alert-zero</html>");
    registerAlertZeroTools(server as unknown as McpServer, {
      alertZeroService,
      analytics: noopAnalyticsClient,
    });
  });

  it("registers every Alert Zero tool plus the UI resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "review-alert-zero-proposals",
        "get-alert-zero-proposal",
        "check-alert-zero-status",
        "list-alert-zero-proposals",
        "get-alert-zero-proposal-detail",
        "get-alert-zero-investigation",
        "approve-alert-zero-proposal",
        "dismiss-alert-zero-proposal",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  it("registers every app-only tool name the view calls", () => {
    for (const name of APP_TOOLS) {
      expect(server.tools.has(name)).toBe(true);
    }
  });

  describe("visibility", () => {
    function uiMeta(name: string): { resourceUri?: string; visibility?: string[] } {
      return (server.tool(name).config._meta?.ui ?? {}) as { resourceUri?: string; visibility?: string[] };
    }

    it("links only review-alert-zero-proposals to the view resource", () => {
      expect(uiMeta("review-alert-zero-proposals").resourceUri).toBe(RESOURCE_URI);
      for (const name of [...MODEL_TOOLS, ...APP_TOOLS].filter((n) => n !== "review-alert-zero-proposals")) {
        expect(uiMeta(name).resourceUri).toBeUndefined();
      }
    });

    it("keeps the model-facing tools visible to the model", () => {
      for (const name of MODEL_TOOLS) {
        expect(uiMeta(name).visibility).toBeUndefined();
      }
    });

    it("hides every view-only tool from the model", () => {
      for (const name of APP_TOOLS) {
        expect(uiMeta(name).visibility).toEqual(["app"]);
      }
    });

    it("only lets the view (a human click) approve or dismiss proposals", () => {
      expect(uiMeta("approve-alert-zero-proposal").visibility).toEqual(["app"]);
      expect(uiMeta("dismiss-alert-zero-proposal").visibility).toEqual(["app"]);
    });
  });

  describe("review-alert-zero-proposals", () => {
    it("forwards scope, category and spaceId and returns an alert-zero bootstrap", async () => {
      const result = makeListResult({ scope: "mine", category: "respond", spaceId: "soc" });
      vi.mocked(alertZeroService.listOpenProposals).mockResolvedValueOnce(result);

      const out = await server.tool("review-alert-zero-proposals").callback({
        scope: "mine",
        category: "respond",
        spaceId: "soc",
      });

      expect(alertZeroService.listOpenProposals).toHaveBeenCalledWith({
        scope: "mine",
        category: "respond",
        spaceId: "soc",
      });
      expect(parseBootstrapToolText(out, "alert-zero")).toEqual(result);
    });

    it("leaves defaults to the service when no inputs are given", async () => {
      vi.mocked(alertZeroService.listOpenProposals).mockResolvedValueOnce(makeListResult());

      await server.tool("review-alert-zero-proposals").callback({});

      expect(alertZeroService.listOpenProposals).toHaveBeenCalledWith({
        scope: undefined,
        category: undefined,
        spaceId: undefined,
      });
    });

    it("passes an unavailable status through in the bootstrap instead of erroring", async () => {
      const status = makeStatus({
        state: "license",
        available: false,
        reason: "Alert Zero requires an Enterprise license",
        remediation: "Upgrade the license",
        canRead: false,
        canDecide: false,
      });
      vi.mocked(alertZeroService.listOpenProposals).mockResolvedValueOnce(
        makeListResult({ status, totalAwaitingDecision: 0, proposals: [] })
      );

      const out = await server.tool("review-alert-zero-proposals").callback({});

      const body = parseBootstrapToolText(out, "alert-zero");
      expect(body.status).toEqual(status);
      expect(body.proposals).toEqual([]);
    });

    it("rejects when the service throws", async () => {
      vi.mocked(alertZeroService.listOpenProposals).mockRejectedValueOnce(new Error("kibana down"));
      await expect(server.tool("review-alert-zero-proposals").callback({})).rejects.toThrow("kibana down");
    });
  });

  describe("get-alert-zero-proposal", () => {
    it("fetches the detail, then the proposal's investigation in the same space", async () => {
      vi.mocked(alertZeroService.getProposalDetail).mockResolvedValueOnce(makeDetail());
      vi.mocked(alertZeroService.getInvestigation).mockResolvedValueOnce(makeInvestigation());

      const out = await server.tool("get-alert-zero-proposal").callback({ proposalId: "p-1", spaceId: "soc" });

      expect(alertZeroService.getProposalDetail).toHaveBeenCalledWith({ proposalId: "p-1", spaceId: "soc" });
      expect(alertZeroService.getInvestigation).toHaveBeenCalledWith({ conversationId: "conv-1", spaceId: "soc" });
      const body = parseToolText<ProposalDigest & { investigationError?: string }>(out);
      expect(body.investigation?.id).toBe("conv-1");
      expect(body.investigationError).toBeUndefined();
    });

    it("keeps the full proposal (comment, actionInput, action metadata) untruncated", async () => {
      const detail = makeDetail();
      vi.mocked(alertZeroService.getProposalDetail).mockResolvedValueOnce(detail);
      vi.mocked(alertZeroService.getInvestigation).mockResolvedValueOnce(makeInvestigation());

      const out = await server.tool("get-alert-zero-proposal").callback({ proposalId: "p-1" });

      const body = parseToolText<ProposalDigest>(out);
      expect(body.proposal).toEqual(detail.proposal);
      expect(body.proposal.comment).toBe(detail.proposal.comment);
      expect(body.proposal.comment.length).toBeGreaterThan(5000);
      expect(body.proposal.actionInput).toEqual(detail.proposal.actionInput);
      expect(body.proposal.action).toEqual(detail.proposal.action);
    });

    it("survives an investigation failure and reports the error", async () => {
      vi.mocked(alertZeroService.getProposalDetail).mockResolvedValueOnce(makeDetail());
      vi.mocked(alertZeroService.getInvestigation).mockRejectedValueOnce(new Error("conversation not found"));

      const out = await server.tool("get-alert-zero-proposal").callback({ proposalId: "p-1" });

      const body = parseToolText<ProposalDigest & { investigationError?: string }>(out);
      expect(body.investigationError).toBe("conversation not found");
      expect(body.investigation).toBeUndefined();
      expect(body.proposal.id).toBe("p-1");
      expect(body.revisionChain).toHaveLength(2);
    });

    it("rejects when the proposal itself cannot be fetched", async () => {
      vi.mocked(alertZeroService.getProposalDetail).mockRejectedValueOnce(new Error("404"));
      await expect(server.tool("get-alert-zero-proposal").callback({ proposalId: "nope" })).rejects.toThrow("404");
      expect(alertZeroService.getInvestigation).not.toHaveBeenCalled();
    });
  });

  describe("check-alert-zero-status", () => {
    it("returns the service status for the requested space", async () => {
      const status = makeStatus({ state: "disabled_in_space", available: false, spaceId: "soc" });
      vi.mocked(alertZeroService.getStatus).mockResolvedValueOnce(status);

      const out = await server.tool("check-alert-zero-status").callback({ spaceId: "soc" });

      expect(alertZeroService.getStatus).toHaveBeenCalledWith({ spaceId: "soc" });
      expect(parseToolText(out)).toEqual(status);
    });
  });

  describe("list-alert-zero-proposals", () => {
    it("returns the raw list result, not a bootstrap envelope", async () => {
      const result = makeListResult();
      vi.mocked(alertZeroService.listOpenProposals).mockResolvedValueOnce(result);

      const out = await server
        .tool("list-alert-zero-proposals")
        .callback({ scope: "unassigned", category: "configure", spaceId: "soc" });

      expect(alertZeroService.listOpenProposals).toHaveBeenCalledWith({
        scope: "unassigned",
        category: "configure",
        spaceId: "soc",
      });
      expect(parseToolText(out)).toEqual(result);
    });
  });

  describe("get-alert-zero-proposal-detail", () => {
    it("returns the full detail", async () => {
      const detail = makeDetail();
      vi.mocked(alertZeroService.getProposalDetail).mockResolvedValueOnce(detail);

      const out = await server.tool("get-alert-zero-proposal-detail").callback({ proposalId: "p-1" });

      expect(alertZeroService.getProposalDetail).toHaveBeenCalledWith({ proposalId: "p-1", spaceId: undefined });
      expect(parseToolText(out)).toEqual(detail);
    });
  });

  describe("get-alert-zero-investigation", () => {
    it("returns the full investigation", async () => {
      const investigation = makeInvestigation();
      vi.mocked(alertZeroService.getInvestigation).mockResolvedValueOnce(investigation);

      const out = await server
        .tool("get-alert-zero-investigation")
        .callback({ conversationId: "conv-1", spaceId: "soc" });

      expect(alertZeroService.getInvestigation).toHaveBeenCalledWith({ conversationId: "conv-1", spaceId: "soc" });
      expect(parseToolText(out)).toEqual(investigation);
    });
  });

  describe("approve-alert-zero-proposal", () => {
    it("forwards the edited action input and rationale", async () => {
      const result: AlertZeroDecisionResult = { ok: true, decisionRecorded: true, proposal: makeProposal() };
      vi.mocked(alertZeroService.approveProposal).mockResolvedValueOnce(result);

      const out = await server.tool("approve-alert-zero-proposal").callback({
        proposalId: "p-1",
        actionInput: { endpoint_ids: ["ep-2"] },
        rationale: "confirmed",
        spaceId: "soc",
      });

      expect(alertZeroService.approveProposal).toHaveBeenCalledWith({
        proposalId: "p-1",
        actionInput: { endpoint_ids: ["ep-2"] },
        rationale: "confirmed",
        spaceId: "soc",
      });
      expect(parseToolText(out)).toEqual(result);
    });

    it("returns a failed decision as-is rather than throwing", async () => {
      const result: AlertZeroDecisionResult = {
        ok: false,
        decisionRecorded: false,
        error: "Proposal is no longer pending",
        httpStatus: 409,
      };
      vi.mocked(alertZeroService.approveProposal).mockResolvedValueOnce(result);

      const out = await server.tool("approve-alert-zero-proposal").callback({ proposalId: "p-1" });

      expect(parseToolText(out)).toEqual(result);
    });
  });

  describe("dismiss-alert-zero-proposal", () => {
    it("forwards the dismiss reason and rationale", async () => {
      const result: AlertZeroDecisionResult = { ok: true, decisionRecorded: true };
      vi.mocked(alertZeroService.dismissProposal).mockResolvedValueOnce(result);

      const out = await server.tool("dismiss-alert-zero-proposal").callback({
        proposalId: "p-1",
        dismissReason: "false_positive",
        rationale: "benign admin script",
      });

      expect(alertZeroService.dismissProposal).toHaveBeenCalledWith({
        proposalId: "p-1",
        dismissReason: "false_positive",
        rationale: "benign admin script",
        spaceId: undefined,
      });
      expect(parseToolText(out)).toEqual(result);
    });
  });

  describe("UI resource", () => {
    it("reads the bundled HTML", async () => {
      const out = await server.resource(RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalledTimes(1);
      expect(out.contents[0].text).toBe("<html>alert-zero</html>");
    });
  });
});

describe("buildProposalDigest", () => {
  it("summarizes the revision chain and siblings", () => {
    const digest = buildProposalDigest(makeDetail());

    expect(digest.revisionChain.map((r) => r.id)).toEqual(["p-0", "p-1"]);
    expect(digest.revisionChain[0]).toEqual({
      id: "p-0",
      title: "Isolate host-1",
      status: "superseded",
      decision: "dismissed",
      revision: 1,
      createdAt: "2026-10-01T00:00:00Z",
      decidedAt: "2026-09-30T00:00:00Z",
      decidedBy: { username: "alice", fullName: null, email: null },
      dismissReason: "other",
      executionError: undefined,
    });
    expect(digest.siblings).toEqual([expect.objectContaining({ id: "p-9", status: "failed", executionError: "boom" })]);
    expect(digest.revisionChain[0]).not.toHaveProperty("comment");
    expect(digest.links).toEqual(makeDetail().links);
    expect(digest.canDecide).toBe(true);
    expect(digest.investigation).toBeUndefined();
  });

  it("includes rule context only when present", () => {
    expect(buildProposalDigest(makeDetail())).not.toHaveProperty("ruleContext");
    const ruleContext = { current: { id: "rule-1", enabled: true } };
    expect(buildProposalDigest(makeDetail({ ruleContext })).ruleContext).toEqual(ruleContext);
  });

  it("digests the investigation's identity, metadata, assignees and alerts in full", () => {
    const investigation = makeInvestigation();
    const digest = buildProposalDigest(makeDetail(), investigation);

    expect(digest.investigation).toMatchObject({
      id: "conv-1",
      title: "Ransomware on host-1",
      agentId: "alertzero-worker",
      metadata: investigation.conversation.metadata,
      assignees: investigation.assignees,
      alerts: investigation.alerts,
    });
  });

  it("truncates long narration but keeps who said it and when", () => {
    const narration = buildProposalDigest(makeDetail(), makeInvestigation()).investigation?.narration;

    expect(narration).toHaveLength(1);
    expect(narration?.[0].at).toBe("2026-10-01T00:00:00Z");
    expect(narration?.[0].actor).toBe("alice");
    expect(narration?.[0].message.startsWith("m".repeat(1500))).toBe(true);
    expect(narration?.[0].message).not.toContain("m".repeat(1501));
    expect(narration?.[0].message).toContain("+3500 chars");
  });

  it("keeps every other event type and counts non-tool, non-reasoning steps", () => {
    const investigation = makeInvestigation();
    const digest = buildProposalDigest(makeDetail(), {
      ...investigation,
      conversation: {
        ...investigation.conversation,
        rounds: [
          {
            ...investigation.conversation.rounds[0],
            steps: [...(investigation.conversation.rounds[0].steps ?? []), { type: "relevant_skills" }, { type: "relevant_skills" }],
          },
        ],
      },
    }).investigation;

    expect(digest?.otherEvents).toEqual([
      { at: "2026-10-01T00:02:00Z", type: "execution_started", actor: undefined, data: "{}" },
    ]);
    expect(digest?.rounds[0].otherStepCounts).toEqual({ relevant_skills: 2 });
    expect(digest?.summarized).toMatch(/summarized/);
  });

  it("lists attachment lifecycle events", () => {
    const events = buildProposalDigest(makeDetail(), makeInvestigation()).investigation?.attachmentEvents;
    expect(events).toEqual([
      {
        at: "2026-10-01T00:01:00Z",
        type: "attachment_added",
        attachment_type: "security.alerts",
        attachment_id: "att-1",
      },
    ]);
  });

  it("uses the current attachment version and truncates large data", () => {
    const attachments = buildProposalDigest(makeDetail(), makeInvestigation()).investigation?.attachments;

    const [alerts, note] = attachments ?? [];
    expect(alerts).toMatchObject({
      id: "att-1",
      type: "security.alerts",
      description: "Alerts",
      current_version: 2,
      active: true,
      origin: "alertzero",
      truncated: true,
    });
    expect(alerts?.data).toHaveLength(2000);
    expect(alerts?.data.startsWith('{"alertIds":["alert-0"')).toBe(true);

    expect(note).toMatchObject({ id: "att-2", active: false, data: "short note" });
    expect(note).not.toHaveProperty("truncated");
  });

  it("bounds round input, response and tool params, and counts reasoning steps", () => {
    const [round] = buildProposalDigest(makeDetail(), makeInvestigation()).investigation?.rounds ?? [];

    expect(round.started_at).toBe("2026-10-01T00:00:00Z");
    expect(round.status).toBe("completed");
    expect(round.input?.startsWith("i".repeat(1500))).toBe(true);
    expect(round.input).not.toContain("i".repeat(1501));
    expect(round.response?.startsWith("r".repeat(3000))).toBe(true);
    expect(round.response).not.toContain("r".repeat(3001));
    expect(round.reasoningCount).toBe(2);
    expect(round.toolCalls).toHaveLength(1);
    expect(round.toolCalls[0].tool_id).toBe("security.alerts.search");
    expect(round.toolCalls[0].resultTypes).toEqual(["esql_results", "other"]);
    expect(round.toolCalls[0].params?.startsWith('{"query":"qqq')).toBe(true);
    expect(round.toolCalls[0].params).not.toContain("q".repeat(500));
  });

  it("keeps the digest far smaller than the raw investigation", () => {
    const investigation = makeInvestigation();
    const digest = buildProposalDigest(makeDetail(), investigation);
    expect(JSON.stringify(digest.investigation).length).toBeLessThan(JSON.stringify(investigation).length / 2);
  });
});

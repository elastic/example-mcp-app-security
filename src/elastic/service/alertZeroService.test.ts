/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, type MockedObject } from "vitest";
import { AlertZeroService } from "./alertZeroService.js";
import { KibanaHttpError } from "../kibana-client/index.js";
import { createMockAlertZeroClient } from "../../test/helpers/mockServiceClients.js";
import type { AlertZeroClient } from "../client/alertZeroClient.js";
import {
  ACTION_WORKFLOW_IDS,
  type AlertZeroCategory,
  type Conversation,
  type ConversationAttachment,
  type ProposalItem,
  type ProposalWithMetadata,
} from "../../shared/alert-zero-types.js";

const KIBANA_URL = "http://localhost:5601/sec";
const CAPS = {
  alertzero: { show: true, write: true },
  proposals: { showProposals: true, decideProposals: true },
  agentBuilder: { show: true },
};

function httpError(status: number | undefined, message?: string): KibanaHttpError {
  const body = message === undefined ? undefined : { statusCode: status, message };
  return new KibanaHttpError(`Kibana [test] ${status ?? "network"}: ${JSON.stringify(body ?? "ECONNREFUSED")}`, status, body);
}

function item(overrides: Partial<ProposalItem> = {}): ProposalItem {
  return {
    id: "p1",
    spaceId: "default",
    conversationId: "c1",
    title: "Isolate host",
    comment: "Contain **WIN-01**",
    actionWorkflowId: ACTION_WORKFLOW_IDS.isolateHost,
    actionInput: { endpoint_ids: ["e1"] },
    status: "pending",
    impact: "high",
    confidence: "high",
    category: "respond",
    origin: "alertzero",
    createdAt: "2026-10-09T12:00:00.000Z",
    conversationAssignees: [],
    ...overrides,
  };
}

function attachment(type: string, data: unknown, overrides: Partial<ConversationAttachment> = {}): ConversationAttachment {
  return { id: `${type}-1`, type, versions: [{ version: 1, data }], current_version: 1, active: true, ...overrides };
}

function conversation(overrides: Partial<Conversation> = {}): Conversation {
  return {
    id: "c1",
    agent_id: "elastic-ai-agent",
    title: "Phishing chain",
    metadata: { status: "open", assignees: ["u1"] },
    rounds: [],
    events: [],
    attachments: [],
    ...overrides,
  };
}

function setup() {
  const alertZeroClient = createMockAlertZeroClient();
  const logger = { warn: vi.fn() };
  const sleep = vi.fn().mockResolvedValue(undefined);
  const service = new AlertZeroService({
    alertZeroClient,
    kibanaUrl: `${KIBANA_URL}/`,
    logger,
    sleep,
    pollAttempts: 3,
    pollIntervalMs: 10,
  });
  return { client: vi.mocked(alertZeroClient), logger, sleep, service };
}

type MockedClient = MockedObject<AlertZeroClient>;

function enable(client: MockedClient, total = 4): void {
  client.getCapabilities.mockResolvedValue(CAPS);
  client.getInvestigationsCount.mockResolvedValue({ total });
}

function serveCategories(
  client: MockedClient,
  rows: Partial<Record<AlertZeroCategory, ProposalItem[]>>,
  totals: Partial<Record<AlertZeroCategory, number>> = {}
): void {
  client.getProposalsByCategory.mockImplementation(async (category, { size, from }) => {
    const all = rows[category] ?? [];
    return { proposals: all.slice(from, from + size), total: totals[category] ?? all.length };
  });
}

describe("AlertZeroService", () => {
  it("trims the trailing slash from kibanaUrl", () => {
    expect(setup().service.kibanaUrl).toBe(KIBANA_URL);
  });

  describe("getStatus", () => {
    it("is enabled when the count probe succeeds", async () => {
      const { client, service } = setup();
      enable(client, 10);

      const status = await service.getStatus();

      expect(client.getCapabilities).toHaveBeenCalledWith("default");
      expect(client.getInvestigationsCount).toHaveBeenCalledWith("default");
      expect(status).toEqual({
        state: "enabled",
        available: true,
        spaceId: "default",
        reason: "Alert Zero is enabled.",
        canRead: true,
        canDecide: true,
        investigationCount: 10,
      });
    });

    it("reports canRead/canDecide false when capabilities can't be read", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockRejectedValue(httpError(500, "boom"));
      client.getInvestigationsCount.mockResolvedValue({ total: 0 });

      const status = await service.getStatus();

      expect(status.state).toBe("enabled");
      expect(status.canRead).toBe(false);
      expect(status.canDecide).toBe(false);
    });

    it("reports canDecide false without proposals.decideProposals", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue({ ...CAPS, proposals: { showProposals: true, decideProposals: false } });
      client.getInvestigationsCount.mockResolvedValue({ total: 0 });

      const status = await service.getStatus();

      expect(status.canRead).toBe(true);
      expect(status.canDecide).toBe(false);
    });

    it("is unreachable on a network failure, even if capabilities say the plugin is off", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue({ navLinks: {} });
      client.getInvestigationsCount.mockRejectedValue(httpError(undefined));

      const status = await service.getStatus();

      expect(status.state).toBe("unreachable");
      expect(status.available).toBe(false);
      expect(status.reason).toBe(`Couldn't reach Kibana at ${KIBANA_URL}: ECONNREFUSED`);
      expect(status.httpStatus).toBeUndefined();
    });

    it("explains an empty network error instead of echoing the transport prefix", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockRejectedValue(new KibanaHttpError('Kibana [test] network: ""'));
      client.getInvestigationsCount.mockRejectedValue(new KibanaHttpError('Kibana [test] network: ""'));

      const status = await service.getStatus();

      expect(status.reason).toBe(
        `Couldn't reach Kibana at ${KIBANA_URL}: no response (connection refused, DNS failure or timeout)`
      );
    });

    it("treats a non-HTTP error as unreachable", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(new TypeError("socket hang up"));

      const status = await service.getStatus();

      expect(status.state).toBe("unreachable");
      expect(status.reason).toBe(`Couldn't reach Kibana at ${KIBANA_URL}: socket hang up`);
    });

    it("is plugin_disabled when capabilities have no alertzero feature", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue({ navLinks: {}, proposals: { showProposals: true } });
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));

      const status = await service.getStatus();

      expect(status).toMatchObject({
        state: "plugin_disabled",
        available: false,
        reason: "Alert Zero isn't installed or is switched off for this Kibana.",
        remediation:
          "Set xpack.alertzero.enabled, xpack.proposals.enabled and xpack.agenticInvestigations.enabled " +
          "to true in kibana.yml and restart Kibana.",
        httpStatus: 404,
        canRead: false,
      });
    });

    it("is missing_privileges on a 404 when alertzero.show is false", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue({ ...CAPS, alertzero: { show: false } });
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));

      const status = await service.getStatus();

      expect(status.state).toBe("missing_privileges");
      expect(status.remediation).toMatch(/Alert Zero \(read\), Proposed Actions \(read; all to approve\/decline\) and Agent Builder \(read\)/);
    });

    it("is disabled_in_space on a 404 when the capability is present", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));

      const status = await service.getStatus({ spaceId: "sumo-demo" });

      expect(client.getInvestigationsCount).toHaveBeenCalledWith("sumo-demo");
      expect(status).toMatchObject({
        state: "disabled_in_space",
        spaceId: "sumo-demo",
        reason: 'Alert Zero is turned off in space "sumo-demo".',
        remediation:
          'Enable the "securitySolution:enableAlertZero" Advanced Setting (Stack Management → Advanced Settings) in space "sumo-demo".',
        httpStatus: 404,
      });
    });

    it("is space_not_found when a 404'd non-default space doesn't exist", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));
      client.spaceExists.mockResolvedValue(false);

      const status = await service.getStatus({ spaceId: "no-such-space" });

      expect(client.spaceExists).toHaveBeenCalledWith("no-such-space");
      expect(status).toMatchObject({
        state: "space_not_found",
        available: false,
        reason: 'Space "no-such-space" doesn\'t exist in this Kibana.',
        httpStatus: 404,
      });
    });

    it("keeps disabled_in_space when the space lookup fails or the space is default", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));
      client.spaceExists.mockRejectedValue(httpError(500, "boom"));

      expect((await service.getStatus({ spaceId: "sumo-demo" })).state).toBe("disabled_in_space");
      expect((await service.getStatus()).state).toBe("disabled_in_space");
      expect(client.spaceExists).toHaveBeenCalledTimes(1);
    });

    it("is missing_privileges when Alert Zero answers but proposals can't be read", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue({ ...CAPS, proposals: { showProposals: false, decideProposals: false } });
      client.getInvestigationsCount.mockResolvedValue({ total: 10 });

      const status = await service.getStatus();

      expect(status.state).toBe("missing_privileges");
      expect(status.available).toBe(false);
      expect(status.reason).toBe(`The API key can use Alert Zero in space "default" but can't read its proposals.`);
      expect(status.remediation).toMatch(/Proposed Actions/);
    });

    it("maps a 404 to disabled_in_space when capabilities failed", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockRejectedValue(httpError(500, "x"));
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));

      expect((await service.getStatus()).state).toBe("disabled_in_space");
    });

    it.each([
      ["AlertZero requires the Security Complete subscription.", "serverless_tier"],
      ["AlertZero requires an active Enterprise license.", "license"],
      ["API [GET /internal/alertzero/investigations/count] is unauthorized for user", "missing_privileges"],
    ])("maps a 403 with %j to %s", async (message, state) => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(403, message));

      const status = await service.getStatus();

      expect(status.state).toBe(state);
      expect(status.httpStatus).toBe(403);
      expect(status.remediation).toBeTruthy();
    });

    it("includes Kibana's message for a 403 privileges failure", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(403, "is unauthorized for user"));

      const status = await service.getStatus();

      expect(status.reason).toBe("The API key isn't allowed to use Alert Zero: is unauthorized for user");
    });

    it("is dependencies_unavailable on a 503", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(503, "AlertZero dependencies are unavailable."));

      const status = await service.getStatus();

      expect(status.state).toBe("dependencies_unavailable");
      expect(status.httpStatus).toBe(503);
      for (const word of ["agentBuilder", "proposals", "agenticInvestigations", "service accounts"]) {
        expect(status.remediation).toContain(word);
      }
    });

    it("is unreachable with Kibana's message for any other status", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(500, "Internal Server Error"));

      const status = await service.getStatus();

      expect(status.state).toBe("unreachable");
      expect(status.httpStatus).toBe(500);
      expect(status.reason).toContain("Internal Server Error");
      expect(status.reason).not.toContain("Kibana [test]");
    });
  });

  describe("listOpenProposals", () => {
    it("returns an empty result without listing when Alert Zero is unavailable", async () => {
      const { client, service } = setup();
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getInvestigationsCount.mockRejectedValue(httpError(404, "Not Found"));

      const out = await service.listOpenProposals({ spaceId: "ad-test", scope: "mine" });

      expect(client.getProposalsByCategory).not.toHaveBeenCalled();
      expect(out).toMatchObject({
        spaceId: "ad-test",
        kibanaUrl: KIBANA_URL,
        scope: "mine",
        category: "all",
        totalAwaitingDecision: 0,
        countsByCategory: { respond: 0, investigate: 0, configure: 0 },
        proposals: [],
        truncated: false,
      });
      expect(out.status.state).toBe("disabled_in_space");
    });

    it("lists every category, drops decided rows, keeps expired-pending rows and sorts by priority", async () => {
      const { client, service } = setup();
      enable(client);
      client.getCurrentUserProfile.mockResolvedValue({ uid: "u1", user: { username: "elastic" } });
      serveCategories(client, {
        respond: [
          item({ id: "low-old", impact: "low", confidence: "low", createdAt: "2026-10-01T00:00:00.000Z" }),
          item({ id: "crit", impact: "critical", confidence: "high" }),
          item({ id: "decided", decision: "approved" }),
          item({ id: "expired", impact: "high", confidence: "high", expiresAt: "2020-01-01T00:00:00.000Z", createdAt: "2026-10-08T00:00:00.000Z" }),
        ],
        investigate: [item({ id: "inv", category: "investigate", impact: "high", confidence: "high", createdAt: "2026-10-10T00:00:00.000Z" })],
        configure: [],
      });

      const out = await service.listOpenProposals();

      expect(client.getProposalsByCategory).toHaveBeenCalledTimes(3);
      for (const category of ["respond", "investigate", "configure"]) {
        expect(client.getProposalsByCategory).toHaveBeenCalledWith(category, { size: 100, from: 0 }, "default");
      }
      expect(out.proposals.map((p) => p.id)).toEqual(["crit", "inv", "expired", "low-old"]);
      expect(out.countsByCategory).toEqual({ respond: 3, investigate: 1, configure: 0 });
      expect(out.totalAwaitingDecision).toBe(4);
      expect(out.currentUser).toEqual({ uid: "u1", username: "elastic" });
      expect(out.truncated).toBe(false);
      expect(out.status.available).toBe(true);
    });

    it("filters by scope and category after counting", async () => {
      const { client, service } = setup();
      enable(client);
      client.getCurrentUserProfile.mockResolvedValue({ uid: "me", user: { username: "elastic" } });
      client.bulkGetUserProfiles.mockResolvedValue([
        { uid: "me", user: { username: "elastic", full_name: "Elastic Admin", email: null } },
        { uid: "other", user: { username: "bob" } },
      ]);
      serveCategories(client, {
        respond: [
          item({ id: "mine", conversationAssignees: ["me"] }),
          item({ id: "theirs", conversationAssignees: ["other"] }),
          item({ id: "nobody" }),
        ],
        configure: [item({ id: "cfg-mine", category: "configure", conversationAssignees: ["me", "other"] })],
      });

      const mine = await service.listOpenProposals({ scope: "mine" });
      expect(mine.proposals.map((p) => p.id).sort()).toEqual(["cfg-mine", "mine"]);
      expect(mine.totalAwaitingDecision).toBe(4);
      expect(mine.countsByCategory).toEqual({ respond: 3, investigate: 0, configure: 1 });
      const cfg = mine.proposals.find((p) => p.id === "cfg-mine");
      expect(cfg?.assignees).toEqual([
        { uid: "me", username: "elastic", fullName: "Elastic Admin" },
        { uid: "other", username: "bob" },
      ]);
      expect(cfg?.assignedToMe).toBe(true);
      expect(client.bulkGetUserProfiles).toHaveBeenCalledWith(expect.arrayContaining(["me", "other"]), "default");

      const unassigned = await service.listOpenProposals({ scope: "unassigned" });
      expect(unassigned.proposals.map((p) => p.id)).toEqual(["nobody"]);

      const configureOnly = await service.listOpenProposals({ category: "configure" });
      expect(configureOnly.proposals.map((p) => p.id)).toEqual(["cfg-mine"]);
      expect(configureOnly.totalAwaitingDecision).toBe(4);
      expect(configureOnly.category).toBe("configure");
    });

    it("paginates each category until from >= total", async () => {
      const { client, service } = setup();
      enable(client);
      const rows = Array.from({ length: 250 }, (_, i) => item({ id: `r${i}` }));
      serveCategories(client, { respond: rows });

      const out = await service.listOpenProposals({ category: "respond" });

      const respondCalls = client.getProposalsByCategory.mock.calls.filter(([c]) => c === "respond");
      expect(respondCalls.map(([, page]) => page)).toEqual([
        { size: 100, from: 0 },
        { size: 100, from: 100 },
        { size: 100, from: 200 },
      ]);
      expect(out.proposals).toHaveLength(250);
      expect(out.countsByCategory.respond).toBe(250);
      expect(out.truncated).toBe(false);
    });

    it("caps each category at 1000 rows and flags truncation", async () => {
      const { client, service } = setup();
      enable(client);
      const rows = Array.from({ length: 1500 }, (_, i) => item({ id: `r${i}`, ...(i === 0 ? { decision: "dismissed" as const } : {}) }));
      serveCategories(client, { respond: rows });

      const out = await service.listOpenProposals();

      const respondCalls = client.getProposalsByCategory.mock.calls.filter(([c]) => c === "respond");
      expect(respondCalls).toHaveLength(10);
      expect(out.proposals).toHaveLength(999);
      expect(out.truncated).toBe(true);
      expect(out.countsByCategory.respond).toBe(1499);
      expect(out.totalAwaitingDecision).toBe(1499);
    });

    it("falls back to bare uids when assignee profiles can't be resolved", async () => {
      const { client, logger, service } = setup();
      enable(client);
      client.getCurrentUserProfile.mockResolvedValue({ uid: "me" });
      client.bulkGetUserProfiles.mockRejectedValue(httpError(500, "nope"));
      serveCategories(client, { respond: [item({ conversationAssignees: ["me", "ghost"] })] });

      const out = await service.listOpenProposals();

      expect(out.proposals[0].assignees).toEqual([{ uid: "me" }, { uid: "ghost" }]);
      expect(out.proposals[0].assignedToMe).toBe(true);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("nope"));
    });

    it("keeps uids the bulk lookup omits and skips the lookup with no assignees", async () => {
      const { client, service } = setup();
      enable(client);
      client.bulkGetUserProfiles.mockResolvedValue([{ uid: "known", user: { username: "k" } }]);
      serveCategories(client, { respond: [item({ conversationAssignees: ["known", "gone"] })] });

      const out = await service.listOpenProposals();
      expect(out.proposals[0].assignees).toEqual([{ uid: "known", username: "k" }, { uid: "gone" }]);

      client.bulkGetUserProfiles.mockClear();
      serveCategories(client, { respond: [item()] });
      await service.listOpenProposals();
      expect(client.bulkGetUserProfiles).not.toHaveBeenCalled();
    });

    it("leaves currentUser undefined when the profile lookup fails, so nothing is 'mine'", async () => {
      const { client, service } = setup();
      enable(client);
      client.getCurrentUserProfile.mockRejectedValue(httpError(404, "Not Found"));
      client.bulkGetUserProfiles.mockResolvedValue([]);
      serveCategories(client, { respond: [item({ conversationAssignees: ["me"] })] });

      const out = await service.listOpenProposals({ scope: "mine" });

      expect(out.currentUser).toBeUndefined();
      expect(out.proposals).toEqual([]);
      expect(out.totalAwaitingDecision).toBe(1);
    });
  });

  it("getProposal delegates with the default space", async () => {
    const { client, service } = setup();
    client.getProposal.mockResolvedValue(item());

    await service.getProposal({ proposalId: "p1" });

    expect(client.getProposal).toHaveBeenCalledWith("p1", "default");
  });

  describe("getProposalDetail", () => {
    const v1 = item({ id: "v1", rootProposalId: "v1", revision: 1, status: "superseded", supersededBy: "v2", createdAt: "2026-10-01T00:00:00.000Z" });
    const v2 = item({ id: "v2", rootProposalId: "v1", supersedes: "v1", revision: 2, createdAt: "2026-10-02T00:00:00.000Z" });
    const other = item({ id: "other", rootProposalId: "other", revision: 1, status: "succeeded", decision: "approved" });

    it("builds the revision chain and siblings and merges the list-only fields", async () => {
      const { client, service } = setup();
      client.getProposal.mockResolvedValue(v2);
      client.listProposalsByConversation.mockResolvedValue({ proposals: [other, v2, v1], total: 3 });
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getConversation.mockResolvedValue(
        conversation({
          attachments: [
            {
              id: "impact",
              type: "investigation_impact",
              current_version: 2,
              versions: [
                { version: 1, data: { entities: [{ id: "host:old" }] } },
                { version: 2, data: { entities: [{ id: "host:win-01" }, { id: "user:jsmith" }, { name: "no id" }] } },
              ],
            },
          ],
        })
      );

      const out = await service.getProposalDetail({ proposalId: "v2", spaceId: "sec" });

      expect(client.getProposal).toHaveBeenCalledWith("v2", "sec");
      expect(client.listProposalsByConversation).toHaveBeenCalledWith("c1", { size: 100, from: 0 }, "sec");
      expect(out.revisionChain.map((p) => p.id)).toEqual(["v1", "v2"]);
      expect(out.siblings.map((p) => p.id)).toEqual(["other"]);
      expect(out.proposal).toMatchObject({
        id: "v2",
        conversationTitle: "Phishing chain",
        conversationAgentId: "elastic-ai-agent",
        conversationAssignees: ["u1"],
        entityIds: ["host:win-01", "user:jsmith"],
      });
      expect(out.links).toEqual({
        alertZero: `${KIBANA_URL}/s/sec/app/alertzero?selectedConversationId=c1`,
        agentBuilder: `${KIBANA_URL}/s/sec/app/agent_builder/agents/elastic-ai-agent/conversations/c1`,
      });
      expect(out).toMatchObject({ kibanaUrl: KIBANA_URL, spaceId: "sec", canDecide: true });
      expect(out.ruleContext).toBeUndefined();
      expect(client.getRuleById).not.toHaveBeenCalled();
    });

    it("orders a failed attempt before the clone that re-offers it, even when revision and createdAt tie", async () => {
      const { client, service } = setup();
      const failed = item({ id: "failed", rootProposalId: "failed", revision: 1, status: "failed", decision: "approved", supersededBy: "clone" });
      const clone = item({ id: "clone", rootProposalId: "failed", revision: 1, supersedes: "failed", previousExecutionError: "boom" });
      client.getProposal.mockResolvedValue(clone);
      client.listProposalsByConversation.mockResolvedValue({ proposals: [clone, failed], total: 2 });
      client.getCapabilities.mockResolvedValue(CAPS);
      client.getConversation.mockResolvedValue(conversation());

      const out = await service.getProposalDetail({ proposalId: "clone" });

      expect(out.revisionChain.map((p) => p.id)).toEqual(["failed", "clone"]);
    });

    it("includes the proposal in its chain even when the list call fails, and degrades softly", async () => {
      const { client, logger, service } = setup();
      client.getProposal.mockResolvedValue(v2);
      client.listProposalsByConversation.mockRejectedValue(httpError(500, "list down"));
      client.getConversation.mockRejectedValue(httpError(404, "Conversation not found"));
      client.getCapabilities.mockRejectedValue(httpError(500, "caps down"));

      const out = await service.getProposalDetail({ proposalId: "v2" });

      expect(out.revisionChain.map((p) => p.id)).toEqual(["v2"]);
      expect(out.siblings).toEqual([]);
      expect(out.proposal).toEqual(v2);
      expect(out.canDecide).toBe(false);
      expect(out.links.agentBuilder).toBe(`${KIBANA_URL}/app/agent_builder/conversations/c1`);
      expect(logger.warn).toHaveBeenCalled();
    });

    it("paginates conversation proposals up to 300", async () => {
      const { client, service } = setup();
      client.getProposal.mockResolvedValue(v2);
      client.getConversation.mockResolvedValue(conversation());
      client.getCapabilities.mockResolvedValue(CAPS);
      client.listProposalsByConversation.mockImplementation(async (_c, { size, from }) => ({
        proposals: Array.from({ length: size }, (_, i) => item({ id: `s${from + i}`, rootProposalId: `s${from + i}` })),
        total: 1000,
      }));

      const out = await service.getProposalDetail({ proposalId: "v2" });

      expect(client.listProposalsByConversation.mock.calls.map(([, page]) => page.from)).toEqual([0, 100, 200]);
      expect(out.siblings).toHaveLength(300);
    });

    function withAction(actionWorkflowId: string, actionInput: Record<string, unknown>): ProposalWithMetadata {
      return item({ id: "r1", actionWorkflowId, actionInput, category: "configure" });
    }

    function setupRule(p: ProposalWithMetadata) {
      const ctx = setup();
      ctx.client.getProposal.mockResolvedValue(p);
      ctx.client.listProposalsByConversation.mockResolvedValue({ proposals: [], total: 0 });
      ctx.client.getConversation.mockResolvedValue(conversation());
      ctx.client.getCapabilities.mockResolvedValue(CAPS);
      return ctx;
    }

    it.each([
      [ACTION_WORKFLOW_IDS.editRule, { id: "so-1", name: "x" }],
      [ACTION_WORKFLOW_IDS.enableRule, { id: "so-1" }],
      [ACTION_WORKFLOW_IDS.addRuleException, { rule_id: "so-1", entries: [] }],
    ])("loads the current rule by saved-object id for %s", async (actionWorkflowId, actionInput) => {
      const { client, service } = setupRule(withAction(actionWorkflowId, actionInput));
      client.getRuleById.mockResolvedValue({ id: "so-1", name: "Rule" });

      const out = await service.getProposalDetail({ proposalId: "r1", spaceId: "sec" });

      expect(client.getRuleById).toHaveBeenCalledWith("so-1", "sec");
      expect(client.getRuleByRuleId).not.toHaveBeenCalled();
      expect(out.ruleContext).toEqual({ current: { id: "so-1", name: "Rule" } });
    });

    it("loads a prebuilt rule by signature id and reports 'Not installed yet' on 404", async () => {
      const p = withAction(ACTION_WORKFLOW_IDS.installPrebuiltRule, { rule_id: "sig-1", version: 3 });
      const { client, service } = setupRule(p);
      client.getRuleByRuleId.mockRejectedValueOnce(httpError(404, 'rule_id: "sig-1" not found'));

      const missing = await service.getProposalDetail({ proposalId: "r1" });
      expect(client.getRuleByRuleId).toHaveBeenCalledWith("sig-1", "default");
      expect(missing.ruleContext).toEqual({ error: "Not installed yet" });

      client.getRuleByRuleId.mockResolvedValueOnce({ rule_id: "sig-1", version: 2 });
      const installed = await service.getProposalDetail({ proposalId: "r1" });
      expect(installed.ruleContext).toEqual({ current: { rule_id: "sig-1", version: 2 } });
    });

    it("reports a rule lookup failure as ruleContext.error with Kibana's message", async () => {
      const { client, service } = setupRule(withAction(ACTION_WORKFLOW_IDS.editRule, { id: "bad" }));
      client.getRuleById.mockRejectedValue(httpError(400, "[request query]: id: Invalid UUID"));

      const out = await service.getProposalDetail({ proposalId: "r1" });

      expect(out.ruleContext).toEqual({ error: "[request query]: id: Invalid UUID" });
    });

    it("reports a missing rule id without calling the rules API", async () => {
      const { client, service } = setupRule(withAction(ACTION_WORKFLOW_IDS.enableRule, {}));

      const out = await service.getProposalDetail({ proposalId: "r1" });

      expect(client.getRuleById).not.toHaveBeenCalled();
      expect(out.ruleContext?.error).toBeTruthy();
    });
  });

  describe("getInvestigation", () => {
    const FULL = "aa3bfbf0690922233db2eedc9d49394d6aeca203abfd47393bebc5d14c2672f7:3f248e5b-80e4-433b-a57b-2ef8d3560315";
    const SHORT_HIT = "c095ee9ebdc61ec87aedbea208995a5fb79be532e8b0740b2c0bf10baa8ecd40";
    const SHORT = `${SHORT_HIT}:3f248e5b-80e4-433b-a57b-2ef8d3560315`;

    it("merges deleted attachments, resolves assignees and enriches alerts", async () => {
      const { client, service } = setup();
      const deleted = attachment("security.alerts", { alertIds: ["gone"] }, { id: "old", active: false });
      const alerts = attachment("security.alerts", { alertIds: [FULL, SHORT] });
      const discovery: ConversationAttachment = {
        id: "ad",
        type: "security.attack_discovery",
        current_version: 2,
        versions: [
          { version: 1, data: { alert_ids: ["stale"] } },
          { version: 2, data: { alert_ids: [FULL, "missing"] } },
        ],
      };
      client.getConversation.mockResolvedValue({
        ...conversation({ attachments: [alerts] }),
        rounds: undefined,
        events: undefined,
      } as unknown as Conversation);
      client.getConversationAttachments.mockResolvedValue({ results: [alerts, discovery, deleted] });
      client.bulkGetUserProfiles.mockResolvedValue([{ uid: "u1", user: { username: "analyst", email: "a@x.io" } }]);
      client.searchAlertsByIds.mockResolvedValue([
        {
          _id: FULL,
          _index: ".internal.alerts-security.alerts-default-000007",
          _source: {
            "kibana.alert.rule.name": "Endpoint Security",
            "kibana.alert.severity": "critical",
            "kibana.alert.risk_score": 99,
            "kibana.alert.reason": "malware",
            "kibana.alert.workflow_status": "open",
            host: { name: "WIN-01" },
            user: { name: ["jsmith"] },
            "@timestamp": "2026-10-08T12:37:48.895Z",
          },
        },
        {
          _id: SHORT_HIT,
          _index: "idx",
          _source: { kibana: { alert: { rule: { name: "Nested" } } }, "host.name": "SRV-02" },
        },
      ]);

      const out = await service.getInvestigation({ conversationId: "c1", spaceId: "sec" });

      expect(client.getConversation).toHaveBeenCalledWith("c1", "sec");
      expect(client.getConversationAttachments).toHaveBeenCalledWith("c1", "sec");
      expect(out.conversation.attachments.map((a) => a.id)).toEqual([alerts.id, "ad", "old"]);
      expect(out.conversation.attachments[2].active).toBe(false);
      expect(out.conversation.rounds).toEqual([]);
      expect(out.conversation.events).toEqual([]);
      expect(out.assignees).toEqual([{ uid: "u1", username: "analyst", email: "a@x.io" }]);

      const [queried, fields] = client.searchAlertsByIds.mock.calls[0];
      expect([...queried].sort()).toEqual(
        [FULL, FULL.split(":")[0], SHORT, SHORT_HIT, "missing", "gone"].sort()
      );
      expect(fields).toEqual(expect.arrayContaining(["kibana.alert.rule.name", "host.name", "@timestamp"]));

      expect(out.alerts[FULL]).toEqual({
        id: FULL,
        index: ".internal.alerts-security.alerts-default-000007",
        ruleName: "Endpoint Security",
        severity: "critical",
        riskScore: 99,
        host: "WIN-01",
        user: "jsmith",
        timestamp: "2026-10-08T12:37:48.895Z",
        reason: "malware",
        workflowStatus: "open",
      });
      expect(out.alerts[SHORT]).toMatchObject({ id: SHORT, index: "idx", ruleName: "Nested", host: "SRV-02" });
      expect(Object.keys(out.alerts).sort()).toEqual([FULL, SHORT].sort());
      expect(out.links).toEqual({
        alertZero: `${KIBANA_URL}/s/sec/app/alertzero?selectedConversationId=c1`,
        agentBuilder: `${KIBANA_URL}/s/sec/app/agent_builder/agents/elastic-ai-agent/conversations/c1`,
      });
    });

    it("falls back to the conversation's attachments and empty alerts when lookups fail", async () => {
      const { client, logger, service } = setup();
      const alerts = attachment("security.alerts", { alertIds: ["a1"] });
      client.getConversation.mockResolvedValue(conversation({ attachments: [alerts], metadata: {} }));
      client.getConversationAttachments.mockRejectedValue(httpError(404, "Not Found"));
      client.searchAlertsByIds.mockRejectedValue(new Error("es down"));

      const out = await service.getInvestigation({ conversationId: "c1" });

      expect(out.conversation.attachments).toEqual([alerts]);
      expect(out.alerts).toEqual({});
      expect(out.assignees).toEqual([]);
      expect(client.bulkGetUserProfiles).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledTimes(2);
    });

    it("caps enrichment at 200 distinct alert ids and skips ES with none", async () => {
      const { client, service } = setup();
      const ids = Array.from({ length: 250 }, (_, i) => `id-${i}`);
      client.getConversation.mockResolvedValue(conversation({ metadata: {} }));
      client.getConversationAttachments.mockResolvedValue({
        results: [attachment("security.alerts", { alertIds: [...ids, ...ids] })],
      });
      client.searchAlertsByIds.mockResolvedValue([]);

      await service.getInvestigation({ conversationId: "c1" });
      expect(client.searchAlertsByIds.mock.calls[0][0]).toHaveLength(200);

      client.searchAlertsByIds.mockClear();
      client.getConversationAttachments.mockResolvedValue({ results: [attachment("platform.proposal", { proposalId: "p" })] });
      const out = await service.getInvestigation({ conversationId: "c1" });
      expect(client.searchAlertsByIds).not.toHaveBeenCalled();
      expect(out.alerts).toEqual({});
    });

    it("throws when the conversation can't be loaded", async () => {
      const { client, service } = setup();
      client.getConversation.mockRejectedValue(httpError(404, "Conversation c1 not found"));
      client.getConversationAttachments.mockResolvedValue({ results: [] });

      await expect(service.getInvestigation({ conversationId: "c1" })).rejects.toBeInstanceOf(KibanaHttpError);
    });
  });

  describe("approveProposal", () => {
    it("sends the stored actionInput by default and polls until the decision is recorded", async () => {
      const { client, sleep, service } = setup();
      const stored = item({ actionInput: { endpoint_ids: ["e1", "e2"] } });
      client.getProposal
        .mockResolvedValueOnce(stored)
        .mockResolvedValueOnce(stored)
        .mockResolvedValueOnce({ ...stored, decision: "approved", status: "executing" });
      client.approveProposal.mockResolvedValue(stored);

      const out = await service.approveProposal({ proposalId: "p1", rationale: "confirmed", spaceId: "sec" });

      expect(client.approveProposal).toHaveBeenCalledWith(
        "p1",
        { actionInput: { endpoint_ids: ["e1", "e2"] }, rationale: "confirmed" },
        "sec"
      );
      expect(out).toEqual({
        ok: true,
        decisionRecorded: true,
        proposal: { ...stored, decision: "approved", status: "executing" },
      });
      expect(sleep).toHaveBeenCalledTimes(1);
      expect(sleep).toHaveBeenCalledWith(10);
    });

    it("uses a caller-supplied actionInput without re-reading the proposal first", async () => {
      const { client, service } = setup();
      client.approveProposal.mockResolvedValue(item());
      client.getProposal.mockResolvedValue(item({ decision: "approved" }));

      const out = await service.approveProposal({ proposalId: "p1", actionInput: { endpoint_ids: ["e9"] } });

      expect(client.approveProposal).toHaveBeenCalledWith("p1", { actionInput: { endpoint_ids: ["e9"] } }, "default");
      expect(client.getProposal).toHaveBeenCalledTimes(1);
      expect(out.decisionRecorded).toBe(true);
    });

    it("returns decisionRecorded false with the last read after the poll budget runs out", async () => {
      const { client, sleep, service } = setup();
      client.approveProposal.mockResolvedValue(item());
      client.getProposal
        .mockResolvedValueOnce(item())
        .mockResolvedValueOnce(item({ title: "read 1" }))
        .mockRejectedValueOnce(httpError(500, "flaky"))
        .mockResolvedValueOnce(item({ title: "read 3" }));

      const out = await service.approveProposal({ proposalId: "p1" });

      expect(out).toEqual({ ok: true, decisionRecorded: false, proposal: item({ title: "read 3" }) });
      expect(client.getProposal).toHaveBeenCalledTimes(4);
      expect(sleep).toHaveBeenCalledTimes(2);
    });

    it("maps a 409 to ok:false with Kibana's message and does not poll", async () => {
      const { client, service } = setup();
      client.approveProposal.mockRejectedValue(httpError(409, "actionInput no longer matches the proposal"));

      const out = await service.approveProposal({ proposalId: "p1", actionInput: { a: 1 } });

      expect(out).toEqual({
        ok: false,
        decisionRecorded: false,
        error: "actionInput no longer matches the proposal",
        httpStatus: 409,
      });
      expect(client.getProposal).not.toHaveBeenCalled();
    });

    it("maps a failed pre-read of the stored actionInput", async () => {
      const { client, service } = setup();
      client.getProposal.mockRejectedValue(httpError(404, "Proposal [p1] not found"));

      const out = await service.approveProposal({ proposalId: "p1" });

      expect(out).toEqual({ ok: false, decisionRecorded: false, error: "Proposal [p1] not found", httpStatus: 404 });
      expect(client.approveProposal).not.toHaveBeenCalled();
    });

    it("rethrows non-HTTP errors", async () => {
      const { client, service } = setup();
      client.approveProposal.mockRejectedValue(new TypeError("bug"));

      await expect(service.approveProposal({ proposalId: "p1", actionInput: {} })).rejects.toThrow("bug");
    });
  });

  describe("dismissProposal", () => {
    it("rejects an unknown reason without calling Kibana", async () => {
      const { client, service } = setup();

      const out = await service.dismissProposal({ proposalId: "p1", dismissReason: "nope" as never });

      expect(out.ok).toBe(false);
      expect(out.decisionRecorded).toBe(false);
      expect(out.error).toContain("false_positive");
      expect(client.dismissProposal).not.toHaveBeenCalled();
    });

    it.each([undefined, "", "   "])("requires a rationale for 'other' (rationale %j)", async (rationale) => {
      const { client, service } = setup();

      const out = await service.dismissProposal({ proposalId: "p1", dismissReason: "other", rationale });

      expect(out).toEqual({
        ok: false,
        decisionRecorded: false,
        error: 'A rationale is required when the dismiss reason is "other".',
      });
      expect(client.dismissProposal).not.toHaveBeenCalled();
    });

    it("POSTs the reason (and rationale when given) then polls", async () => {
      const { client, service } = setup();
      client.dismissProposal.mockResolvedValue(item());
      client.getProposal.mockResolvedValue(item({ decision: "dismissed", status: "no_action", dismissReason: "other" }));

      const out = await service.dismissProposal({
        proposalId: "p1",
        dismissReason: "other",
        rationale: "test host",
        spaceId: "sec",
      });

      expect(client.dismissProposal).toHaveBeenCalledWith("p1", { dismissReason: "other", rationale: "test host" }, "sec");
      expect(out.ok).toBe(true);
      expect(out.decisionRecorded).toBe(true);

      client.dismissProposal.mockClear();
      await service.dismissProposal({ proposalId: "p1", dismissReason: "false_positive" });
      expect(client.dismissProposal).toHaveBeenCalledWith("p1", { dismissReason: "false_positive" }, "default");
    });

    it("maps HTTP failures to ok:false", async () => {
      const { client, service } = setup();
      client.dismissProposal.mockRejectedValue(httpError(403, "is unauthorized for user"));

      const out = await service.dismissProposal({ proposalId: "p1", dismissReason: "duplicate" });

      expect(out).toEqual({ ok: false, decisionRecorded: false, error: "is unauthorized for user", httpStatus: 403 });
    });
  });
});

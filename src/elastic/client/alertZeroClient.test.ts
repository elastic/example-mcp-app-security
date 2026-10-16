/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { AlertZeroClient } from "./alertZeroClient.js";
import { KibanaHttpError } from "../kibana-client/kibana-http-error.js";
import {
  createMockEsClient,
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const V1_HEADERS = { "elastic-api-version": "1" };
const PUBLIC_HEADERS = { "elastic-api-version": "2023-10-31" };

function setup() {
  const esClient = createMockEsClient();
  const kibanaClient = createMockKibanaClient();
  const client = new AlertZeroClient({ esClient, kibanaClient });
  return { esClient, kibanaClient, client };
}

describe("AlertZeroClient", () => {
  describe("space prefix", () => {
    it("omits the prefix for the default space and when no space is given", async () => {
      const { kibanaClient, client } = setup();
      kibanaClient.get.mockResolvedValue(dataEnvelope({ total: 1 }));

      await client.getInvestigationsCount();
      await client.getInvestigationsCount("default");

      expect(kibanaClient.get).toHaveBeenNthCalledWith(1, "/internal/alertzero/investigations/count", {
        headers: V1_HEADERS,
      });
      expect(kibanaClient.get).toHaveBeenNthCalledWith(2, "/internal/alertzero/investigations/count", {
        headers: V1_HEADERS,
      });
    });

    it("prefixes /s/<space> (URI-encoded) for other spaces", async () => {
      const { kibanaClient, client } = setup();
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ total: 0 }));

      const out = await client.getInvestigationsCount("my space");

      expect(kibanaClient.get).toHaveBeenCalledWith("/s/my%20space/internal/alertzero/investigations/count", {
        headers: V1_HEADERS,
      });
      expect(out).toEqual({ total: 0 });
    });
  });

  it("getCapabilities POSTs an empty applications list without a version header", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ alertzero: { show: true } }));

    const caps = await client.getCapabilities("sec");

    expect(kibanaClient.post).toHaveBeenCalledWith("/s/sec/api/core/capabilities", { applications: [] });
    expect(caps).toEqual({ alertzero: { show: true } });
  });

  it("spaceExists GETs the spaces API, is false on 404 and rethrows other errors", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get
      .mockResolvedValueOnce(dataEnvelope({ id: "sec" }))
      .mockRejectedValueOnce(new KibanaHttpError("Kibana [test] 404: {}", 404))
      .mockRejectedValueOnce(new KibanaHttpError("Kibana [test] 500: {}", 500));

    await expect(client.spaceExists("my space")).resolves.toBe(true);
    expect(kibanaClient.get).toHaveBeenCalledWith("/api/spaces/space/my%20space", { headers: PUBLIC_HEADERS });
    await expect(client.spaceExists("nope")).resolves.toBe(false);
    await expect(client.spaceExists("boom")).rejects.toThrow("500");
  });

  it("getProposalsByCategory GETs the category route with size/from", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ proposals: [], total: 0 }));

    await client.getProposalsByCategory("respond", { size: 100, from: 200 }, "sec");

    expect(kibanaClient.get).toHaveBeenCalledWith("/s/sec/internal/alertzero/proposals/category/respond", {
      params: { size: 100, from: 200 },
      headers: V1_HEADERS,
    });
  });

  it("getProposal GETs /internal/proposals/{id}", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ id: "p1" }));

    const out = await client.getProposal("p1");

    expect(kibanaClient.get).toHaveBeenCalledWith("/internal/proposals/p1", { headers: V1_HEADERS });
    expect(out).toEqual({ id: "p1" });
  });

  it("listProposalsByConversation filters by conversationId without excludeSuperseded", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ proposals: [], total: 0 }));

    await client.listProposalsByConversation("c1", { size: 100, from: 0 }, "sec");

    expect(kibanaClient.get).toHaveBeenCalledWith("/s/sec/internal/proposals", {
      params: { conversationId: "c1", size: 100, from: 0 },
      headers: V1_HEADERS,
    });
  });

  it("getConversation GETs the Agent Builder public route", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ id: "c1" }));

    await client.getConversation("c1", "sec");

    expect(kibanaClient.get).toHaveBeenCalledWith("/s/sec/api/agent_builder/conversations/c1", {
      headers: PUBLIC_HEADERS,
    });
  });

  it("getConversationAttachments asks for deleted attachments too", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ results: [{ id: "a1" }] }));

    const out = await client.getConversationAttachments("c1");

    expect(kibanaClient.get).toHaveBeenCalledWith("/api/agent_builder/conversations/c1/attachments", {
      params: { include_deleted: true },
      headers: PUBLIC_HEADERS,
    });
    expect(out).toEqual({ results: [{ id: "a1" }] });
  });

  it("getCurrentUserProfile GETs the security user profile WITHOUT a version header", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ uid: "u1", user: { username: "elastic" } }));

    const out = await client.getCurrentUserProfile();

    expect(kibanaClient.get).toHaveBeenCalledWith("/internal/security/user_profile");
    expect(out.uid).toBe("u1");
  });

  it("bulkGetUserProfiles POSTs uids with the avatar data path", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope([{ uid: "u1" }]));

    await client.bulkGetUserProfiles(["u1", "u2"], "sec");

    expect(kibanaClient.post).toHaveBeenCalledWith("/s/sec/internal/security/user_profile/_bulk_get", {
      uids: ["u1", "u2"],
      dataPath: "avatar",
    });
  });

  it("approveProposal POSTs the body to /approve", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ id: "p1" }));

    await client.approveProposal("p1", { actionInput: { a: 1 }, rationale: "ok" }, "sec");

    expect(kibanaClient.post).toHaveBeenCalledWith(
      "/s/sec/internal/proposals/p1/approve",
      { actionInput: { a: 1 }, rationale: "ok" },
      { headers: V1_HEADERS }
    );
  });

  it("dismissProposal POSTs the body to /dismiss", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ id: "p1" }));

    await client.dismissProposal("p1", { dismissReason: "false_positive" });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      "/internal/proposals/p1/dismiss",
      { dismissReason: "false_positive" },
      { headers: V1_HEADERS }
    );
  });

  it("getRuleById and getRuleByRuleId use the id / rule_id query params", async () => {
    const { kibanaClient, client } = setup();
    kibanaClient.get.mockResolvedValue(dataEnvelope({ id: "r" }));

    await client.getRuleById("so-1", "sec");
    await client.getRuleByRuleId("sig-1");

    expect(kibanaClient.get).toHaveBeenNthCalledWith(1, "/s/sec/api/detection_engine/rules", {
      params: { id: "so-1" },
      headers: PUBLIC_HEADERS,
    });
    expect(kibanaClient.get).toHaveBeenNthCalledWith(2, "/api/detection_engine/rules", {
      params: { rule_id: "sig-1" },
      headers: PUBLIC_HEADERS,
    });
  });

  it("searchAlertsByIds POSTs an ids query with _source filtering to every alerts index", async () => {
    const { esClient, client } = setup();
    esClient.post.mockResolvedValueOnce(
      dataEnvelope({ hits: { hits: [{ _id: "a", _index: "i", _source: {} }] } })
    );

    const hits = await client.searchAlertsByIds(["a", "b"], ["host.name"]);

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-*/_search",
      { size: 2, query: { ids: { values: ["a", "b"] } }, _source: ["host.name"] },
      { params: { ignore_unavailable: "true", allow_no_indices: "true" } }
    );
    expect(hits).toEqual([{ _id: "a", _index: "i", _source: {} }]);
  });
});

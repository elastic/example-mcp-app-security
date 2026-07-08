/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { CasesService } from "./casesService.js";
import { createMockCasesClient } from "../../test/helpers/mockServiceClients.js";

describe("CasesService", () => {
  describe("listCases", () => {
    it("uses securitySolution defaults and forwards optional filters as params", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.findCases).mockResolvedValueOnce({
        cases: [],
        total: 0,
        page: 1,
        perPage: 20,
      });

      const service = new CasesService({ casesClient });
      await service.listCases({
        status: "open",
        severity: "high",
        tags: ["a", "b"],
        search: "ransom",
      });

      expect(casesClient.findCases).toHaveBeenCalledWith({
        owner: "securitySolution",
        page: "1",
        perPage: "20",
        sortField: "createdAt",
        sortOrder: "desc",
        status: "open",
        severity: "high",
        tags: "a,b",
        search: "ransom",
      });
    });

    it("omits optional params when not supplied", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.findCases).mockResolvedValueOnce({
        cases: [],
        total: 0,
        page: 1,
        perPage: 20,
      });

      const service = new CasesService({ casesClient });
      await service.listCases({});

      const params = vi.mocked(casesClient.findCases).mock.calls[0][0];
      expect(params).not.toHaveProperty("status");
      expect(params).not.toHaveProperty("severity");
      expect(params).not.toHaveProperty("tags");
      expect(params).not.toHaveProperty("search");
    });
  });

  it("getCase delegates to the client", async () => {
    const casesClient = createMockCasesClient();
    const fakeCase = { id: "c1" };
    vi.mocked(casesClient.getCase).mockResolvedValueOnce(fakeCase as never);

    const service = new CasesService({ casesClient });
    const out = await service.getCase("c1");

    expect(casesClient.getCase).toHaveBeenCalledWith("c1");
    expect(out).toBe(fakeCase);
  });

  it("createCase passes a sane default body (owner, connector, settings)", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.createCase).mockResolvedValueOnce({
      id: "c1",
    } as never);

    const service = new CasesService({ casesClient });
    await service.createCase({ title: "T", description: "D" });

    expect(casesClient.createCase).toHaveBeenCalledWith({
      title: "T",
      description: "D",
      tags: [],
      severity: "low",
      owner: "securitySolution",
      connector: { id: "none", name: "none", type: ".none", fields: null },
      settings: { syncAlerts: true },
    });
  });

  it("updateCase wraps the update inside the bulk envelope with id+version", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.updateCases).mockResolvedValueOnce([] as never);

    const service = new CasesService({ casesClient });
    await service.updateCase("c1", "v", { status: "closed" });

    expect(casesClient.updateCases).toHaveBeenCalledWith({
      cases: [{ id: "c1", version: "v", status: "closed" }],
    });
  });

  it("addComment posts a user comment with securitySolution ownership", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

    const service = new CasesService({ casesClient });
    await service.addComment("c1", "hi");

    expect(casesClient.addComment).toHaveBeenCalledWith("c1", {
      type: "user",
      comment: "hi",
      owner: "securitySolution",
    });
  });

  it("attachAlert posts an alert comment shaped for Kibana cases", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

    const service = new CasesService({ casesClient });
    await service.attachAlert("c1", "a1", "alert-idx", "r1", "Rule One");

    expect(casesClient.addComment).toHaveBeenCalledWith("c1", {
      type: "alert",
      alertId: "a1",
      index: "alert-idx",
      rule: { id: "r1", name: "Rule One" },
      owner: "securitySolution",
    });
  });

  describe("attachAlertsByIds", () => {
    it("returns 0 immediately when ids is empty (no calls)", async () => {
      const casesClient = createMockCasesClient();
      const service = new CasesService({ casesClient });

      const out = await service.attachAlertsByIds("c1", []);
      expect(out).toBe(0);
      expect(casesClient.searchAlertsByIds).not.toHaveBeenCalled();
      expect(casesClient.addComment).not.toHaveBeenCalled();
    });

    it("returns 0 and logs when the alert lookup fails entirely", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.searchAlertsByIds).mockRejectedValueOnce(
        new Error("down")
      );
      const logger = { warn: vi.fn() };

      const service = new CasesService({ casesClient, logger });
      const out = await service.attachAlertsByIds("c1", ["a", "b"]);

      expect(out).toBe(0);
      expect(casesClient.addComment).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("down")
      );
    });

    it("deduplicates alert ids before the lookup", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.searchAlertsByIds).mockResolvedValueOnce([]);

      const service = new CasesService({ casesClient });
      await service.attachAlertsByIds("c1", ["a1", "a1", "a2"]);

      expect(casesClient.searchAlertsByIds).toHaveBeenCalledWith(
        [".alerts-security.alerts-default"],
        ["a1", "a2"]
      );
    });

    it("skips sourceless hits and counts only successful attachments", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.searchAlertsByIds).mockResolvedValueOnce([
        {
          _id: "a1",
          _index: "i1",
          _source: {
            "kibana.alert.rule.uuid": "r1",
            "kibana.alert.rule.name": "Rule",
          },
        },
        { _id: "a3", _index: "i1" /* no _source */ },
      ]);
      vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

      const service = new CasesService({ casesClient });
      const out = await service.attachAlertsByIds("c1", ["a1", "a2", "a3"]);

      expect(casesClient.searchAlertsByIds).toHaveBeenCalledWith(
        [".alerts-security.alerts-default"],
        ["a1", "a2", "a3"]
      );

      expect(out).toBe(1);
      expect(casesClient.addComment).toHaveBeenCalledTimes(1);
      expect(casesClient.addComment).toHaveBeenCalledWith("c1", {
        type: "alert",
        alertId: "a1",
        index: "i1",
        rule: { id: "r1", name: "Rule" },
        owner: "securitySolution",
      });
    });

    it("falls back to 'Unknown Rule' when the rule.name is missing", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.searchAlertsByIds).mockResolvedValueOnce([
        { _id: "a1", _index: "i1", _source: {} },
      ]);
      vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

      const service = new CasesService({ casesClient });
      await service.attachAlertsByIds("c1", ["a1"]);

      expect(casesClient.addComment).toHaveBeenCalledWith(
        "c1",
        expect.objectContaining({
          rule: { id: "", name: "Unknown Rule" },
        })
      );
    });

    it("continues when an individual attach fails and only counts successes", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.searchAlertsByIds).mockResolvedValueOnce([
        {
          _id: "a1",
          _index: "i1",
          _source: { "kibana.alert.rule.uuid": "r", "kibana.alert.rule.name": "R" },
        },
        {
          _id: "a2",
          _index: "i1",
          _source: { "kibana.alert.rule.uuid": "r", "kibana.alert.rule.name": "R" },
        },
      ]);
      vi.mocked(casesClient.addComment)
        .mockResolvedValueOnce({})
        .mockRejectedValueOnce(new Error("nope"));

      const service = new CasesService({ casesClient });
      const out = await service.attachAlertsByIds("c1", ["a1", "a2"]);

      expect(out).toBe(1);
      expect(casesClient.addComment).toHaveBeenCalledTimes(2);
    });
  });

  it("getCasesForAlert delegates straight through to the client", async () => {
    const casesClient = createMockCasesClient();
    const result = [{ id: "c1", title: "T" }];
    vi.mocked(casesClient.getCasesForAlert).mockResolvedValueOnce(result);

    const service = new CasesService({ casesClient });
    const out = await service.getCasesForAlert("a1");

    expect(casesClient.getCasesForAlert).toHaveBeenCalledWith("a1");
    expect(out).toBe(result);
  });

  it("getComments uses perPage=100 and sortOrder=asc", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getCommentsFind).mockResolvedValueOnce({
      comments: [],
      total: 0,
    });

    const service = new CasesService({ casesClient });
    await service.getComments("c1");

    expect(casesClient.getCommentsFind).toHaveBeenCalledWith("c1", {
      perPage: "100",
      sortOrder: "asc",
    });
  });

  it("getUserProfile pulls the avatar dataPath and reshapes the response", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getUserProfile).mockResolvedValueOnce({
      user: { username: "k" },
      data: { avatar: { initials: "K", color: "blue" } },
    });

    const service = new CasesService({ casesClient });
    const out = await service.getUserProfile();

    expect(casesClient.getUserProfile).toHaveBeenCalledWith({
      dataPath: "avatar",
    });
    expect(out).toEqual({
      username: "k",
      avatar: { initials: "K", color: "blue" },
    });
  });

  it("getUserProfile returns sane fallbacks when fields are missing", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getUserProfile).mockResolvedValueOnce(
      {} as never
    );

    const service = new CasesService({ casesClient });
    const out = await service.getUserProfile();

    expect(out).toEqual({ username: "", avatar: {} });
  });

  describe("getCaseAlerts", () => {
    it("enriches up to 20 attachments with one ids-query search and falls back to bare records for missing hits", async () => {
      const attachments = Array.from({ length: 22 }, (_, i) => ({
        id: `a${i}`,
        index: ".alerts-security.alerts-default",
        attached_at: "t",
      }));

      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.getCaseAlerts).mockResolvedValueOnce(attachments);

      vi.mocked(casesClient.searchAlertsByIds).mockResolvedValueOnce([
        {
          _id: "a0",
          _index: ".internal.alerts-security.alerts-default-000002",
          _source: {
            "kibana.alert.rule.name": "RuleA",
            "kibana.alert.severity": "high",
            host: { name: "h1" },
            user: { name: "u1" },
            "kibana.alert.reason": "r",
          },
        },
      ]);

      const service = new CasesService({ casesClient });
      const out = await service.getCaseAlerts("c1");

      // Stops at the enrichment cap; one batched lookup, not per-alert calls.
      expect(out).toHaveLength(20);
      expect(casesClient.searchAlertsByIds).toHaveBeenCalledTimes(1);
      expect(casesClient.searchAlertsByIds).toHaveBeenCalledWith(
        [".alerts-security.alerts-default"],
        attachments.slice(0, 20).map((a) => a.id)
      );
      expect(out[0]).toEqual({
        id: "a0",
        index: ".alerts-security.alerts-default",
        attached_at: "t",
        rule: "RuleA",
        severity: "high",
        host: "h1",
        user: "u1",
        reason: "r",
      });
      // Alerts the search did not return fall back to the bare record.
      expect(out[1]).toEqual({
        id: "a1",
        index: ".alerts-security.alerts-default",
        attached_at: "t",
      });
    });

    it("deduplicates the recorded indices across attachments", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.getCaseAlerts).mockResolvedValueOnce([
        { id: "a1", index: ".alerts-security.alerts-default", attached_at: "t" },
        { id: "a2", index: ".alerts-security.alerts-default", attached_at: "t" },
        {
          id: "a3",
          index: ".internal.alerts-security.alerts-default-000001",
          attached_at: "t",
        },
      ]);
      vi.mocked(casesClient.searchAlertsByIds).mockResolvedValueOnce([]);

      const service = new CasesService({ casesClient });
      await service.getCaseAlerts("c1");

      expect(casesClient.searchAlertsByIds).toHaveBeenCalledWith(
        [
          ".alerts-security.alerts-default",
          ".internal.alerts-security.alerts-default-000001",
        ],
        ["a1", "a2", "a3"]
      );
    });

    it("returns bare records and logs when the enrichment search fails", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.getCaseAlerts).mockResolvedValueOnce([
        { id: "a1", index: ".alerts-security.alerts-default", attached_at: "t" },
      ]);
      vi.mocked(casesClient.searchAlertsByIds).mockRejectedValueOnce(
        new Error("search down")
      );
      const logger = { warn: vi.fn() };

      const service = new CasesService({ casesClient, logger });
      const out = await service.getCaseAlerts("c1");

      expect(out).toEqual([
        { id: "a1", index: ".alerts-security.alerts-default", attached_at: "t" },
      ]);
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("search down")
      );
    });

    it("skips the search entirely when the case has no attachments", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.getCaseAlerts).mockResolvedValueOnce([]);

      const service = new CasesService({ casesClient });
      const out = await service.getCaseAlerts("c1");

      expect(out).toEqual([]);
      expect(casesClient.searchAlertsByIds).not.toHaveBeenCalled();
    });
  });
});

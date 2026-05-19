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

      expect(casesClient.findCases).toHaveBeenCalledWith(
        {
          owner: "securitySolution",
          page: "1",
          perPage: "20",
          sortField: "createdAt",
          sortOrder: "desc",
          status: "open",
          severity: "high",
          tags: "a,b",
          search: "ransom",
        },
        undefined
      );
    });

    it("forwards namespace to the client when supplied", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.findCases).mockResolvedValueOnce({
        cases: [],
        total: 0,
        page: 1,
        perPage: 20,
      });

      const service = new CasesService({ casesClient });
      await service.listCases({ namespace: "soc" });

      expect(casesClient.findCases).toHaveBeenCalledWith(
        expect.any(Object),
        "soc"
      );
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

    expect(casesClient.getCase).toHaveBeenCalledWith("c1", undefined);
    expect(out).toBe(fakeCase);
  });

  it("getCase forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getCase).mockResolvedValueOnce({ id: "c1" } as never);

    const service = new CasesService({ casesClient });
    await service.getCase("c1", "soc");

    expect(casesClient.getCase).toHaveBeenCalledWith("c1", "soc");
  });

  it("createCase passes a sane default body (owner, connector, settings) and no namespace when unset", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.createCase).mockResolvedValueOnce({
      id: "c1",
    } as never);

    const service = new CasesService({ casesClient });
    await service.createCase({ title: "T", description: "D" });

    expect(casesClient.createCase).toHaveBeenCalledWith(
      {
        title: "T",
        description: "D",
        tags: [],
        severity: "low",
        owner: "securitySolution",
        connector: { id: "none", name: "none", type: ".none", fields: null },
        settings: { syncAlerts: true },
      },
      undefined
    );
  });

  it("createCase forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.createCase).mockResolvedValueOnce({
      id: "c1",
    } as never);

    const service = new CasesService({ casesClient });
    await service.createCase({
      title: "T",
      description: "D",
      namespace: "soc",
    });

    expect(casesClient.createCase).toHaveBeenCalledWith(
      expect.objectContaining({ title: "T", description: "D" }),
      "soc"
    );
  });

  it("updateCase wraps the update inside the bulk envelope with id+version", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.updateCases).mockResolvedValueOnce([] as never);

    const service = new CasesService({ casesClient });
    await service.updateCase("c1", "v", { status: "closed" });

    expect(casesClient.updateCases).toHaveBeenCalledWith(
      { cases: [{ id: "c1", version: "v", status: "closed" }] },
      undefined
    );
  });

  it("updateCase forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.updateCases).mockResolvedValueOnce([] as never);

    const service = new CasesService({ casesClient });
    await service.updateCase("c1", "v", { status: "closed" }, "soc");

    expect(casesClient.updateCases).toHaveBeenCalledWith(
      expect.any(Object),
      "soc"
    );
  });

  it("addComment posts a user comment with securitySolution ownership", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

    const service = new CasesService({ casesClient });
    await service.addComment("c1", "hi");

    expect(casesClient.addComment).toHaveBeenCalledWith(
      "c1",
      { type: "user", comment: "hi", owner: "securitySolution" },
      undefined
    );
  });

  it("addComment forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

    const service = new CasesService({ casesClient });
    await service.addComment("c1", "hi", "soc");

    expect(casesClient.addComment).toHaveBeenCalledWith(
      "c1",
      expect.objectContaining({ type: "user", comment: "hi" }),
      "soc"
    );
  });

  it("attachAlert posts an alert comment shaped for Kibana cases", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

    const service = new CasesService({ casesClient });
    await service.attachAlert("c1", "a1", "alert-idx", "r1", "Rule One");

    expect(casesClient.addComment).toHaveBeenCalledWith(
      "c1",
      {
        type: "alert",
        alertId: "a1",
        index: "alert-idx",
        rule: { id: "r1", name: "Rule One" },
        owner: "securitySolution",
      },
      undefined
    );
  });

  it("attachAlert forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

    const service = new CasesService({ casesClient });
    await service.attachAlert("c1", "a1", "i", "r", "R", "soc");

    expect(casesClient.addComment).toHaveBeenCalledWith(
      "c1",
      expect.objectContaining({ alertId: "a1" }),
      "soc"
    );
  });

  describe("attachAlertsByIds", () => {
    it("returns 0 immediately when ids is empty (no calls)", async () => {
      const casesClient = createMockCasesClient();
      const service = new CasesService({ casesClient });

      const out = await service.attachAlertsByIds("c1", []);
      expect(out).toBe(0);
      expect(casesClient.mgetAlerts).not.toHaveBeenCalled();
      expect(casesClient.addComment).not.toHaveBeenCalled();
    });

    it("returns 0 and swallows errors when mget fails entirely", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.mgetAlerts).mockRejectedValueOnce(
        new Error("down")
      );

      const service = new CasesService({ casesClient });
      const out = await service.attachAlertsByIds("c1", ["a", "b"]);

      expect(out).toBe(0);
      expect(casesClient.addComment).not.toHaveBeenCalled();
    });

    it("skips not-found / sourceless docs and counts only successful attachments", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.mgetAlerts).mockResolvedValueOnce({
        docs: [
          {
            _id: "a1",
            _index: "i1",
            found: true,
            _source: {
              "kibana.alert.rule.uuid": "r1",
              "kibana.alert.rule.name": "Rule",
            },
          },
          { _id: "a2", _index: "i1", found: false },
          { _id: "a3", _index: "i1", found: true /* no _source */ },
        ],
      });
      vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

      const service = new CasesService({ casesClient });
      const out = await service.attachAlertsByIds("c1", ["a1", "a2", "a3"]);

      expect(out).toBe(1);
      expect(casesClient.addComment).toHaveBeenCalledTimes(1);
      expect(casesClient.addComment).toHaveBeenCalledWith(
        "c1",
        {
          type: "alert",
          alertId: "a1",
          index: "i1",
          rule: { id: "r1", name: "Rule" },
          owner: "securitySolution",
        },
        undefined
      );
    });

    it("falls back to 'Unknown Rule' when the rule.name is missing", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.mgetAlerts).mockResolvedValueOnce({
        docs: [
          {
            _id: "a1",
            _index: "i1",
            found: true,
            _source: {},
          },
        ],
      });
      vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

      const service = new CasesService({ casesClient });
      await service.attachAlertsByIds("c1", ["a1"]);

      expect(casesClient.addComment).toHaveBeenCalledWith(
        "c1",
        expect.objectContaining({
          rule: { id: "", name: "Unknown Rule" },
        }),
        undefined
      );
    });

    it("forwards namespace to mgetAlerts and to each attachment call", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.mgetAlerts).mockResolvedValueOnce({
        docs: [
          {
            _id: "a1",
            _index: "i1",
            found: true,
            _source: {
              "kibana.alert.rule.uuid": "r1",
              "kibana.alert.rule.name": "Rule",
            },
          },
        ],
      });
      vi.mocked(casesClient.addComment).mockResolvedValueOnce({});

      const service = new CasesService({ casesClient });
      await service.attachAlertsByIds("c1", ["a1"], "soc");

      expect(casesClient.mgetAlerts).toHaveBeenCalledWith(["a1"], "soc");
      expect(casesClient.addComment).toHaveBeenCalledWith(
        "c1",
        expect.objectContaining({ alertId: "a1" }),
        "soc"
      );
    });

    it("continues when an individual attach fails and only counts successes", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.mgetAlerts).mockResolvedValueOnce({
        docs: [
          {
            _id: "a1",
            _index: "i1",
            found: true,
            _source: { "kibana.alert.rule.uuid": "r", "kibana.alert.rule.name": "R" },
          },
          {
            _id: "a2",
            _index: "i1",
            found: true,
            _source: { "kibana.alert.rule.uuid": "r", "kibana.alert.rule.name": "R" },
          },
        ],
      });
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

    expect(casesClient.getCasesForAlert).toHaveBeenCalledWith("a1", undefined);
    expect(out).toBe(result);
  });

  it("getCasesForAlert forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getCasesForAlert).mockResolvedValueOnce([]);

    const service = new CasesService({ casesClient });
    await service.getCasesForAlert("a1", "soc");

    expect(casesClient.getCasesForAlert).toHaveBeenCalledWith("a1", "soc");
  });

  it("getComments uses perPage=100 and sortOrder=asc", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getCommentsFind).mockResolvedValueOnce({
      comments: [],
      total: 0,
    });

    const service = new CasesService({ casesClient });
    await service.getComments("c1");

    expect(casesClient.getCommentsFind).toHaveBeenCalledWith(
      "c1",
      { perPage: "100", sortOrder: "asc" },
      undefined
    );
  });

  it("getComments forwards namespace to the client when supplied", async () => {
    const casesClient = createMockCasesClient();
    vi.mocked(casesClient.getCommentsFind).mockResolvedValueOnce({
      comments: [],
      total: 0,
    });

    const service = new CasesService({ casesClient });
    await service.getComments("c1", "soc");

    expect(casesClient.getCommentsFind).toHaveBeenCalledWith(
      "c1",
      expect.any(Object),
      "soc"
    );
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
    it("enriches up to 20 attachments and falls back to bare records on lookup errors", async () => {
      const attachments = Array.from({ length: 22 }, (_, i) => ({
        id: `a${i}`,
        index: ".alerts-security.alerts-default",
        attached_at: "t",
      }));

      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.getCaseAlerts).mockResolvedValueOnce(attachments);

      vi.mocked(casesClient.getAlertDocument).mockImplementation(
        async (_idx, id) => {
          if (id === "a0") {
            return {
              _source: {
                "kibana.alert.rule.name": "RuleA",
                "kibana.alert.severity": "high",
                host: { name: "h1" },
                user: { name: "u1" },
                "kibana.alert.reason": "r",
              },
            };
          }
          throw new Error("doc gone");
        }
      );

      const service = new CasesService({ casesClient });
      const out = await service.getCaseAlerts("c1");

      // Stops at the enrichment cap.
      expect(out).toHaveLength(20);
      expect(casesClient.getAlertDocument).toHaveBeenCalledTimes(20);
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
      // Failed lookups fall back to the bare record.
      expect(out[1]).toEqual({
        id: "a1",
        index: ".alerts-security.alerts-default",
        attached_at: "t",
      });
    });

    it("forwards namespace to the client lookup", async () => {
      const casesClient = createMockCasesClient();
      vi.mocked(casesClient.getCaseAlerts).mockResolvedValueOnce([]);

      const service = new CasesService({ casesClient });
      await service.getCaseAlerts("c1", "soc");

      expect(casesClient.getCaseAlerts).toHaveBeenCalledWith("c1", "soc");
    });
  });
});

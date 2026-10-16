/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import {
  formatDiscoveryMarkdown,
  iocCategories,
  iocsToCsv,
  splitRenderAttachments,
  toReplacementMap,
} from "./attachments";
import { deadlineLabel, getPhaseMeta, isWorkerActor } from "./helpers";
import { buildTimeline } from "./timeline";
import { makeInvestigation } from "./testFixtures";

describe("getPhaseMeta", () => {
  it.each([
    [{ status: "pending" }, "Needs review", "primary"],
    [{ status: "pending", decision: "approved" as const }, "Applying", "primary"],
    [{ status: "executing", decision: "approved" as const }, "Applying", "primary"],
    [{ status: "succeeded", decision: "approved" as const }, "Applied", "success"],
    [{ status: "failed", decision: "approved" as const }, "Failed", "danger"],
    [{ status: "no_action", decision: "approved" as const }, "Approved – no action", "default"],
    [{ status: "no_action", decision: "dismissed" as const }, "Declined", "default"],
    [{ status: "expired" }, "Expired", "warning"],
    [{ status: "superseded" }, "Superseded", "default"],
    [{ status: "brand_new_status" }, "Brand new status", "default"],
  ])("%o → %s", (input, label, tone) => {
    const meta = getPhaseMeta(input);
    expect(meta.label).toBe(label);
    expect(meta.tone).toBe(tone);
  });
});

describe("deadlineLabel", () => {
  const now = Date.parse("2026-10-11T12:00:00Z");
  it("reports relative time and past deadlines", () => {
    expect(deadlineLabel("2026-10-11T15:00:00Z", now)).toBe("Expires in 3h");
    expect(deadlineLabel("2026-10-14T12:00:00Z", now)).toBe("Expires in 3d");
    expect(deadlineLabel("2026-10-11T11:00:00Z", now)).toBe("Past deadline");
    expect(deadlineLabel(undefined, now)).toBeUndefined();
  });
});

describe("isWorkerActor", () => {
  it("treats service accounts and alertzero_ users as Workers", () => {
    expect(isWorkerActor({ username: "kibana/Test" })).toBe(true);
    expect(isWorkerActor({ username: "alertzero_triage" })).toBe(true);
    expect(isWorkerActor({ id: 'realm:["_service_account","x"]' })).toBe(true);
    expect(isWorkerActor({ username: "elastic", id: "u_123" })).toBe(false);
  });
});

describe("buildTimeline", () => {
  it("folds round replays into the round and keeps every other event, in order", () => {
    const { conversation } = makeInvestigation();
    const timeline = buildTimeline(conversation);
    const round = timeline.find((i) => i.kind === "round");
    expect(round && round.kind === "round" && round.coveredEvents.map((e) => e.id)).toEqual(["ev-8", "ev-9", "ev-10", "ev-11"]);
    expect(timeline.filter((i) => i.kind === "event").map((i) => (i.kind === "event" ? i.event.id : ""))).toEqual([
      "ev-1",
      "ev-2",
      "ev-3",
      "ev-4",
      "ev-5",
      "ev-6",
      "ev-7",
    ]);
    expect(timeline[timeline.length - 1].kind).toBe("round");
  });

  it("keeps an execution step the round does not contain", () => {
    const { conversation } = makeInvestigation();
    const stray = {
      id: "ev-stray",
      type: "execution_step",
      created_at: "2026-10-09T14:00:01.000Z",
      data: { step: { type: "tool_call", tool_call_id: "tc-unknown", tool_id: "x" } },
    };
    const timeline = buildTimeline({ ...conversation, events: [...conversation.events, stray] });
    expect(timeline.some((i) => i.kind === "event" && i.event.id === "ev-stray")).toBe(true);
  });

  it("shows every event when there are no rounds", () => {
    const { conversation } = makeInvestigation();
    expect(buildTimeline({ events: conversation.events, rounds: [] })).toHaveLength(conversation.events.length);
  });
});

describe("attachment helpers", () => {
  it("de-anonymizes Attack Discovery markdown and highlights field values", () => {
    const replacements = toReplacementMap({ "uuid-1": "WIN-ANALYST01" });
    expect(formatDiscoveryMarkdown("on {{ host.name uuid-1 }} now", replacements)).toBe("on `WIN-ANALYST01` now");
    expect(toReplacementMap([{ uuid: "a", value: "b" }])).toEqual({ a: "b" });
  });

  it("builds an escaped IOC CSV with category,value,comment", () => {
    const csv = iocsToCsv(iocCategories({ ips: [{ value: "1.2.3.4", comment: 'C2, "primary"' }], extra_list: ["x"] }));
    expect(csv).toBe('category,value,comment\nips,1.2.3.4,"C2, ""primary"""\nextra_list,x,\n');
  });

  it("splits render_attachment placeholders out of agent responses", () => {
    expect(splitRenderAttachments('Before\n<render_attachment id="a-1" />\nAfter')).toEqual([
      { kind: "markdown", text: "Before\n" },
      { kind: "attachment", id: "a-1" },
      { kind: "markdown", text: "\nAfter" },
    ]);
  });
});

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import type { AlertZeroProposalCard } from "../../../../shared/alert-zero-types.js";
import {
  categoryBucket,
  computeKpis,
  expiryInfo,
  groupProposals,
  highestImpact,
  impactTone,
  userInitials,
} from "./list-model.js";

const NOW = Date.parse("2026-10-11T12:00:00Z");
const HOUR = 3_600_000;

function card(overrides: Partial<AlertZeroProposalCard> & { id: string }): AlertZeroProposalCard {
  return {
    conversationId: "conv-1",
    title: `Proposal ${overrides.id}`,
    status: "pending",
    impact: "medium",
    confidence: "medium",
    createdAt: new Date(NOW - HOUR).toISOString(),
    hasPreviousExecutionError: false,
    assignees: [],
    assignedToMe: false,
    priorityScore: 50,
    commentExcerpt: "",
    targets: [],
    ...overrides,
  };
}

describe("categoryBucket", () => {
  it("maps known categories case-insensitively and everything else to other", () => {
    expect(categoryBucket("respond")).toBe("respond");
    expect(categoryBucket("Configure")).toBe("configure");
    expect(categoryBucket("triage")).toBe("other");
    expect(categoryBucket(undefined)).toBe("other");
  });
});

describe("groupProposals", () => {
  const cards = [
    card({ id: "a", category: "configure", conversationId: "c2", investigationTitle: "Rule tuning" }),
    card({ id: "b", category: "respond", conversationId: "c1", investigationTitle: "Ransomware on host-7", impact: "high" }),
    card({ id: "c", category: "mystery", conversationId: "c3" }),
    card({ id: "d", category: "respond", conversationId: "c2", investigationTitle: "Rule tuning", impact: "critical" }),
  ];

  it("orders category groups Respond → Investigate → Configure → Other and keeps priority order inside", () => {
    const groups = groupProposals(cards, "category");
    expect(groups.map((g) => g.key)).toEqual(["respond", "configure", "other"]);
    expect(groups.map((g) => g.tone)).toEqual(["danger", "primary", "default"]);
    expect(groups[0].cards.map((c) => c.id)).toEqual(["b", "d"]);
  });

  it("groups by investigation in first-seen order with a fallback title and the highest impact", () => {
    const groups = groupProposals(cards, "investigation");
    expect(groups.map((g) => g.label)).toEqual(["Rule tuning", "Ransomware on host-7", "Untitled investigation"]);
    expect(groups[0].cards.map((c) => c.id)).toEqual(["a", "d"]);
    expect(groups[0].topImpact).toBe("critical");
  });
});

describe("impact helpers", () => {
  it("maps impact to Alert Zero badge tones", () => {
    expect(impactTone("critical")).toBe("danger");
    expect(impactTone("high")).toBe("danger");
    expect(impactTone("medium")).toBe("warning");
    expect(impactTone("low")).toBe("hollow");
  });

  it("finds the highest impact", () => {
    expect(highestImpact([card({ id: "x", impact: "low" }), card({ id: "y", impact: "high" })])).toBe("high");
  });
});

describe("expiryInfo", () => {
  it("returns null without a deadline", () => {
    expect(expiryInfo(undefined, NOW)).toBeNull();
    expect(expiryInfo("not a date", NOW)).toBeNull();
  });

  it("flags past deadlines as danger", () => {
    expect(expiryInfo(new Date(NOW - 1000).toISOString(), NOW)).toMatchObject({ label: "Past deadline", tone: "danger" });
  });

  it("warns inside 24h and stays muted beyond", () => {
    expect(expiryInfo(new Date(NOW + 21 * HOUR + 5 * 60_000).toISOString(), NOW)).toMatchObject({
      label: "Expires in 21h",
      tone: "warning",
    });
    expect(expiryInfo(new Date(NOW + 40 * 60_000).toISOString(), NOW)).toMatchObject({ label: "Expires in 40m" });
    expect(expiryInfo(new Date(NOW + 3 * 24 * HOUR).toISOString(), NOW)).toMatchObject({
      label: "Expires in 3d",
      tone: "muted",
    });
  });
});

describe("computeKpis", () => {
  it("counts impact, deadlines and assignment from the loaded cards", () => {
    const kpis = computeKpis(
      [
        card({ id: "1", impact: "critical", expiresAt: new Date(NOW + 2 * HOUR).toISOString() }),
        card({ id: "2", impact: "high", expiresAt: new Date(NOW - HOUR).toISOString(), assignees: [{ uid: "u1" }], assignedToMe: true }),
        card({ id: "3", impact: "low", expiresAt: new Date(NOW + 48 * HOUR).toISOString(), assignees: [{ uid: "u2" }] }),
      ],
      NOW,
    );
    expect(kpis).toEqual({ highImpact: 2, expiringSoon: 1, pastDeadline: 1, unassigned: 1, assignedToMe: 1 });
  });
});

describe("userInitials", () => {
  it("prefers full name, then username, then uid", () => {
    expect(userInitials({ uid: "u_1", fullName: "Ada Lovelace", username: "ada" })).toBe("AL");
    expect(userInitials({ uid: "u_1", username: "grace.hopper" })).toBe("GH");
    expect(userInitials({ uid: "u_1", username: "root" })).toBe("RO");
    expect(userInitials({ uid: "u_3q9" })).toBe("U3");
  });
});

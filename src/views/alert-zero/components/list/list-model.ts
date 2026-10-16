/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  ALERT_ZERO_CATEGORIES,
  type AlertZeroCategory,
  type AlertZeroProposalCard,
  type ProposalConfidence,
  type ProposalImpact,
  type ResolvedUser,
} from "../../../../shared/alert-zero-types";

export type BadgeTone = "danger" | "warning" | "primary" | "success" | "default" | "hollow";
export type CategoryBucket = AlertZeroCategory | "other";
export type GroupBy = "category" | "investigation";

export const CATEGORY_ORDER: readonly CategoryBucket[] = [...ALERT_ZERO_CATEGORIES, "other"];

export const CATEGORY_LABEL: Record<CategoryBucket, string> = {
  respond: "Respond",
  investigate: "Investigate",
  configure: "Configure",
  other: "Other",
};

export const CATEGORY_TONE: Record<CategoryBucket, BadgeTone> = {
  respond: "danger",
  investigate: "warning",
  configure: "primary",
  other: "default",
};

export function categoryBucket(category: string | undefined): CategoryBucket {
  const key = category?.toLowerCase();
  return ALERT_ZERO_CATEGORIES.find((c) => c === key) ?? "other";
}

const IMPACT_RANK: Record<ProposalImpact, number> = { low: 1, medium: 2, high: 3, critical: 4 };

const IMPACT_LABEL: Record<ProposalImpact, string> = {
  critical: "Critical impact",
  high: "High impact",
  medium: "Medium impact",
  low: "Low impact",
};

const CONFIDENCE_LABEL: Record<ProposalConfidence, string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};

export function impactLabel(impact: ProposalImpact): string {
  return IMPACT_LABEL[impact] ?? `${impact} impact`;
}

export function impactTone(impact: ProposalImpact): BadgeTone {
  if (impact === "critical" || impact === "high") return "danger";
  if (impact === "medium") return "warning";
  return "hollow";
}

export function confidenceLabel(confidence: ProposalConfidence): string {
  return CONFIDENCE_LABEL[confidence] ?? `${confidence} confidence`;
}

export function isHighImpact(impact: ProposalImpact): boolean {
  return impact === "critical" || impact === "high";
}

export function highestImpact(cards: readonly AlertZeroProposalCard[]): ProposalImpact {
  let top: ProposalImpact = "low";
  for (const c of cards) {
    if ((IMPACT_RANK[c.impact] ?? 0) > IMPACT_RANK[top]) top = c.impact;
  }
  return top;
}

export const UNTITLED_INVESTIGATION = "Untitled investigation";

export function investigationLabel(card: Pick<AlertZeroProposalCard, "investigationTitle">): string {
  return card.investigationTitle?.trim() || UNTITLED_INVESTIGATION;
}

export interface ProposalGroup {
  readonly key: string;
  readonly kind: GroupBy;
  readonly label: string;
  /** Category colour; investigation groups use `default`. */
  readonly tone: BadgeTone;
  readonly topImpact: ProposalImpact;
  readonly cards: readonly AlertZeroProposalCard[];
}

/**
 * Bucket cards without reordering them, so each group keeps the server's
 * priority order. Category groups follow Alert Zero's Respond → Investigate →
 * Configure order; investigation groups follow their highest-priority card.
 */
export function groupProposals(
  cards: readonly AlertZeroProposalCard[],
  groupBy: GroupBy,
): ProposalGroup[] {
  const buckets = new Map<string, { label: string; tone: BadgeTone; cards: AlertZeroProposalCard[] }>();
  for (const card of cards) {
    let key: string;
    let label: string;
    let tone: BadgeTone;
    if (groupBy === "category") {
      const bucket = categoryBucket(card.category);
      key = bucket;
      label = CATEGORY_LABEL[bucket];
      tone = CATEGORY_TONE[bucket];
    } else {
      key = card.conversationId;
      label = investigationLabel(card);
      tone = "default";
    }
    const existing = buckets.get(key);
    if (existing) existing.cards.push(card);
    else buckets.set(key, { label, tone, cards: [card] });
  }

  const keys =
    groupBy === "category"
      ? CATEGORY_ORDER.filter((k) => buckets.has(k))
      : [...buckets.keys()];

  return keys.map((key) => {
    const b = buckets.get(key)!;
    return { key, kind: groupBy, label: b.label, tone: b.tone, topImpact: highestImpact(b.cards), cards: b.cards };
  });
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function formatRemaining(ms: number): string {
  const mins = Math.max(1, Math.floor(ms / MINUTE));
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

export type ExpiryTone = "danger" | "warning" | "muted";

export interface ExpiryInfo {
  readonly label: string;
  readonly tone: ExpiryTone;
  readonly title: string;
}

export function expiryInfo(expiresAt: string | undefined, now: number = Date.now()): ExpiryInfo | null {
  if (!expiresAt) return null;
  const at = Date.parse(expiresAt);
  if (Number.isNaN(at)) return null;
  const when = new Date(at).toLocaleString();
  const remaining = at - now;
  if (remaining <= 0) return { label: "Past deadline", tone: "danger", title: `Deadline was ${when}` };
  return {
    label: `Expires in ${formatRemaining(remaining)}`,
    tone: remaining < DAY ? "warning" : "muted",
    title: `Expires ${when}`,
  };
}

export interface ListKpis {
  readonly highImpact: number;
  readonly expiringSoon: number;
  readonly pastDeadline: number;
  readonly unassigned: number;
  readonly assignedToMe: number;
}

export function computeKpis(cards: readonly AlertZeroProposalCard[], now: number = Date.now()): ListKpis {
  let highImpact = 0;
  let expiringSoon = 0;
  let pastDeadline = 0;
  let unassigned = 0;
  let assignedToMe = 0;
  for (const c of cards) {
    if (isHighImpact(c.impact)) highImpact++;
    if (c.assignees.length === 0) unassigned++;
    if (c.assignedToMe) assignedToMe++;
    const at = c.expiresAt ? Date.parse(c.expiresAt) : NaN;
    if (!Number.isNaN(at)) {
      if (at <= now) pastDeadline++;
      else if (at - now < DAY) expiringSoon++;
    }
  }
  return { highImpact, expiringSoon, pastDeadline, unassigned, assignedToMe };
}

export function userDisplayName(user: ResolvedUser): string {
  return user.fullName?.trim() || user.username?.trim() || user.email?.trim() || user.uid;
}

export function userInitials(user: ResolvedUser): string {
  const source = user.fullName?.trim() || user.username?.trim() || user.uid;
  const words = source.split(/[\s._@-]+/).filter(Boolean);
  const initials =
    words.length >= 2 ? `${words[0][0]}${words[1][0]}` : source.replace(/[^\p{L}\p{N}]/gu, "").slice(0, 2);
  return initials.toUpperCase() || "?";
}

function hashString(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = ((hash << 5) - hash + value.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

/** Mid-lightness hue so white initials stay legible on both themes. */
export function avatarColor(seed: string): string {
  return `hsl(${hashString(seed) % 360} 45% 42%)`;
}

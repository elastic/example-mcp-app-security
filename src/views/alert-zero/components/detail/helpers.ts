/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  ProposalDecision,
  ProposalUser,
  ResolvedUser,
} from "../../../../shared/alert-zero-types";

export type BadgeTone = "danger" | "warning" | "primary" | "success" | "default" | "hollow";

export type ProposalPhase =
  | "needs_review"
  | "applying"
  | "applied"
  | "declined"
  | "failed"
  | "expired"
  | "superseded"
  | "approved_no_action"
  | "no_action"
  | "unknown";

interface PhaseMeta {
  readonly label: string;
  readonly tone: BadgeTone;
  readonly banner?: string;
  readonly hint?: string;
}

const PHASE_META: Record<Exclude<ProposalPhase, "unknown">, PhaseMeta> = {
  needs_review: { label: "Needs review", tone: "primary" },
  applying: {
    label: "Applying",
    tone: "primary",
    banner: "Applying",
    hint: "Approved — the action is running. Typically takes 3-5 minutes.",
  },
  applied: { label: "Applied", tone: "success", banner: "Applied successfully" },
  declined: { label: "Declined", tone: "default", banner: "Declined" },
  failed: { label: "Failed", tone: "danger", banner: "Action failed" },
  expired: {
    label: "Expired",
    tone: "warning",
    banner: "Expired",
    hint: "This proposal expired before a decision was made and can no longer be actioned.",
  },
  superseded: {
    label: "Superseded",
    tone: "default",
    banner: "Superseded",
    hint: "A newer revision of this proposal replaced it.",
  },
  approved_no_action: {
    label: "Approved – no action",
    tone: "default",
    banner: "Approved — no action to run",
  },
  no_action: { label: "No action", tone: "default", banner: "Closed — no action to run" },
};

interface PhaseInput {
  readonly status: string;
  readonly decision?: ProposalDecision;
}

/** Mirrors `kbn-proposals-ui` `approvedStatusFor`, extended with superseded and undecided states. */
export function getProposalPhase(p: PhaseInput): ProposalPhase {
  if (p.status === "expired") return "expired";
  if (p.status === "superseded") return "superseded";
  if (p.decision === "dismissed") return "declined";
  if (p.decision === "approved") {
    if (p.status === "failed") return "failed";
    if (p.status === "pending" || p.status === "executing") return "applying";
    if (p.status === "no_action") return "approved_no_action";
    return "applied";
  }
  switch (p.status) {
    case "pending":
      return "needs_review";
    case "executing":
      return "applying";
    case "succeeded":
      return "applied";
    case "failed":
      return "failed";
    case "no_action":
      return "no_action";
    default:
      return "unknown";
  }
}

export function getPhaseMeta(p: PhaseInput): PhaseMeta & { readonly phase: ProposalPhase } {
  const phase = getProposalPhase(p);
  if (phase === "unknown") return { phase, label: humanize(p.status || "unknown"), tone: "default" };
  return { phase, ...PHASE_META[phase] };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asStringArray(value: unknown): string[] {
  return asArray(value)
    .map((v) => asString(v))
    .filter((v): v is string => v !== undefined);
}

export function sentenceCase(value: string): string {
  return value.length > 0 ? `${value[0].toUpperCase()}${value.slice(1)}` : value;
}

/** `security.attack_discovery` → `Security attack discovery`, `kill_descendants` → `Kill descendants`. */
export function humanize(value: string): string {
  return sentenceCase(
    String(value)
      .replace(/([a-z])([A-Z])/g, "$1 $2")
      .replace(/[._-]+/g, " ")
      .trim()
      .toLowerCase(),
  );
}

export function safeJson(value: unknown, space = 2): string {
  try {
    const out = JSON.stringify(value, null, space);
    return out === undefined ? String(value) : out;
  } catch {
    return String(value);
  }
}

/** JSON with object keys sorted, for comparing values regardless of key order. */
export function stableJson(value: unknown): string {
  const seen = new WeakSet<object>();
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(norm);
    if (isRecord(v)) {
      if (seen.has(v)) return "[circular]";
      seen.add(v);
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, norm(v[k])]),
      );
    }
    return v;
  };
  return safeJson(norm(value), 0);
}

export function parseTime(iso: string | undefined): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? undefined : t;
}

export function formatDateTime(iso: string | undefined): string {
  if (!iso) return "—";
  const t = parseTime(iso);
  if (t === undefined) return iso;
  return new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatTime(iso: string | undefined): string {
  const t = parseTime(iso);
  if (t === undefined) return iso ?? "";
  return new Date(t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function spanLabel(ms: number): string {
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${Math.max(mins, 1)}m`;
  const hrs = Math.round(mins / 60);
  if (hrs < 48) return `${hrs}h`;
  return `${Math.round(hrs / 24)}d`;
}

/** Header caption deadline: `Expires in 3h` / `Past deadline`, or undefined without a deadline. */
export function deadlineLabel(expiresAt: string | undefined, now = Date.now()): string | undefined {
  const t = parseTime(expiresAt);
  if (t === undefined) return expiresAt ? `Expires ${expiresAt}` : undefined;
  return t <= now ? "Past deadline" : `Expires in ${spanLabel(t - now)}`;
}

export function formatDuration(ms: unknown): string | undefined {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return undefined;
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s - m * 60)}s`;
}

export function formatNumber(value: unknown): string | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : undefined;
}

type AnyUser = Partial<ProposalUser> & Partial<ResolvedUser>;

export function userLabel(user: AnyUser | null | undefined): string {
  if (!user) return "Unknown";
  return user.fullName || user.username || user.email || user.uid || user.profileUid || "Unknown";
}

/** Service accounts (`kibana/…`, `realm:["_service_account"…`) and `alertzero_*` users are Workers. */
export function isWorkerActor(actor: { username?: unknown; id?: unknown } | undefined): boolean {
  if (!actor) return false;
  const username = asString(actor.username) ?? "";
  const id = asString(actor.id) ?? "";
  return (
    username.startsWith("alertzero_") ||
    /^kibana\//.test(username) ||
    id.includes("_service_account")
  );
}

export function initials(name: string): string {
  return (
    name
      .replace(/[^\p{L}\p{N}\s]/gu, " ")
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0]?.toUpperCase() ?? "")
      .join("") || "?"
  );
}

export function truncateText(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function severityTone(severity: string | undefined): BadgeTone {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "success";
    default:
      return "default";
  }
}

/** CSS colour variable for a severity stripe. */
export function severityColor(severity: string | undefined): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "var(--severity-critical)";
    case "high":
      return "var(--severity-high)";
    case "medium":
      return "var(--severity-medium)";
    case "low":
      return "var(--severity-low)";
    default:
      return "var(--border)";
  }
}

export function csvCell(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

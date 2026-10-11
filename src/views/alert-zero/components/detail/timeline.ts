/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  Conversation,
  ConversationEvent,
  ConversationRound,
  RoundStep,
} from "../../../../shared/alert-zero-types";
import { asString, isRecord, parseTime, stableJson } from "./helpers";

export type TimelineItem =
  | {
      readonly kind: "event";
      readonly key: string;
      readonly at?: string;
      readonly event: ConversationEvent;
    }
  | {
      readonly kind: "round";
      readonly key: string;
      readonly at?: string;
      readonly index: number;
      readonly round: ConversationRound;
      /** Events that replay this round (`user_message`, `execution_*`); shown only as raw JSON. */
      readonly coveredEvents: readonly ConversationEvent[];
    };

const SLACK_MS = 2000;

export function stepSignature(step: RoundStep | Record<string, unknown>): string {
  const type = asString(step.type) ?? "";
  const toolCallId = asString(step.tool_call_id);
  if (type === "tool_call" && toolCallId) return `tc:${toolCallId}`;
  const reasoning = asString(step.reasoning);
  if (type === "reasoning" && reasoning !== undefined) return `r:${reasoning}`;
  return `${type}:${stableJson(step)}`;
}

interface RoundIndex {
  readonly start?: number;
  readonly end?: number;
  readonly traceId?: string;
  readonly usage?: string;
  readonly message?: string;
  readonly signatures: ReadonlySet<string>;
}

function indexRound(round: ConversationRound): RoundIndex {
  const start = parseTime(round.started_at);
  const duration = typeof round.time_to_last_token === "number" ? round.time_to_last_token : 0;
  return {
    start,
    end: start === undefined ? undefined : start + duration,
    traceId: round.trace_id,
    usage: round.model_usage ? stableJson(round.model_usage) : undefined,
    message: round.input?.message,
    signatures: new Set((round.steps ?? []).map((s) => stepSignature(s))),
  };
}

function withinWindow(t: number | undefined, r: RoundIndex): boolean {
  if (t === undefined || r.start === undefined || r.end === undefined) return false;
  return t >= r.start - SLACK_MS && t <= r.end + SLACK_MS;
}

/**
 * Agent Builder stores chat turns twice: as `rounds` and as `user_message` +
 * `execution_*` events. Returns the round index an event replays, or -1 when
 * the event carries information no round has (so it must be shown).
 */
function coveringRound(event: ConversationEvent, rounds: readonly RoundIndex[]): number {
  const t = parseTime(event.created_at);
  const data = isRecord(event.data) ? event.data : {};
  for (let i = 0; i < rounds.length; i++) {
    const r = rounds[i];
    if (event.type === "user_message") {
      const message = asString(data.message);
      if (message !== undefined && message === r.message && t !== undefined && r.start !== undefined && Math.abs(t - r.start) <= SLACK_MS) {
        return i;
      }
      continue;
    }
    if (event.type === "execution_step") {
      if (isRecord(data.step) && r.signatures.has(stepSignature(data.step))) return i;
      continue;
    }
    if (event.type.startsWith("execution_")) {
      const traceId = asString(data.trace_id);
      if (traceId && r.traceId && traceId === r.traceId) return i;
      if (r.usage && isRecord(data.model_usage) && stableJson(data.model_usage) === r.usage) return i;
      if (event.type === "execution_started" && withinWindow(t, r)) return i;
    }
  }
  return -1;
}

/** One chronological list of events and rounds, with round replays folded into their round. */
export function buildTimeline(conversation: Pick<Conversation, "events" | "rounds">): TimelineItem[] {
  const rounds = conversation.rounds ?? [];
  const events = conversation.events ?? [];
  const index = rounds.map(indexRound);
  const covered: ConversationEvent[][] = rounds.map(() => []);

  type Sortable = { item: TimelineItem; t?: number; order: number; rank: number };
  const rows: Sortable[] = [];

  events.forEach((event, i) => {
    const owner = coveringRound(event, index);
    if (owner >= 0) {
      covered[owner].push(event);
      return;
    }
    rows.push({
      item: { kind: "event", key: `e:${event.id ?? i}:${i}`, at: event.created_at, event },
      t: parseTime(event.created_at),
      order: i,
      rank: 0,
    });
  });

  rounds.forEach((round, i) => {
    rows.push({
      item: {
        kind: "round",
        key: `r:${round.id ?? i}:${i}`,
        at: round.started_at,
        index: i,
        round,
        coveredEvents: covered[i],
      },
      t: index[i].start,
      order: i,
      rank: 1,
    });
  });

  rows.sort((a, b) => {
    if (a.t === undefined && b.t === undefined) return a.rank - b.rank || a.order - b.order;
    if (a.t === undefined) return 1;
    if (b.t === undefined) return -1;
    return a.t - b.t || a.rank - b.rank || a.order - b.order;
  });
  return rows.map((r) => r.item);
}

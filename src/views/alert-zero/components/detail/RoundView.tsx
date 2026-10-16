/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from "react";
import classNames from "classnames";
import type { ConversationRound, RoundStep, ToolResult } from "../../../../shared/alert-zero-types";
import { useDetailContext } from "./DetailContext";
import {
  PROPOSAL_ATTACHMENT_TYPE,
  attachmentTypeLabel,
  proposalIdOfAttachment,
  splitRenderAttachments,
} from "./attachments";
import {
  asArray,
  asString,
  formatDuration,
  formatNumber,
  humanize,
  isRecord,
  safeJson,
  truncateText,
} from "./helpers";
import { PaperclipIcon, ThinkIcon, ToolIcon } from "./icons";
import {
  Avatar,
  Badge,
  Callout,
  CodeBlock,
  Collapsible,
  CopyButton,
  JsonBlock,
  KeyValueTree,
  Markdown,
  ValueTree,
} from "./primitives";
import { ProposalRef } from "./ProposalRow";
import type { TimelineItem } from "./timeline";

// ─── Attachment references inside messages ───────────────────────────────

export function AttachmentChip({
  id,
  prefix,
  suffix,
}: {
  readonly id: string;
  readonly prefix?: string;
  readonly suffix?: string;
}) {
  const { attachmentsById, jumpToAttachment } = useDetailContext();
  const a = attachmentsById.get(id);
  return (
    <button
      type="button"
      className="azd-att-chip"
      onClick={() => jumpToAttachment(id)}
      title={a?.description ? `${a.description} — show in Evidence` : `${id} — show in Evidence`}
    >
      <PaperclipIcon />
      {prefix && <span>{prefix}</span>}
      <strong>{a ? attachmentTypeLabel(a.type) : truncateText(id, 32)}</strong>
      {a?.description && <span className="azd-att-chip-desc">{truncateText(a.description, 60)}</span>}
      {suffix && <span className="azd-muted">{suffix}</span>}
    </button>
  );
}

function InlineAttachment({ id }: { readonly id: string }) {
  const { attachmentsById } = useDetailContext();
  const a = attachmentsById.get(id);
  if (a?.type === PROPOSAL_ATTACHMENT_TYPE) {
    const proposalId = proposalIdOfAttachment(a);
    if (proposalId) return <ProposalRef id={proposalId} />;
  }
  return <AttachmentChip id={id} />;
}

/** Markdown with `<render_attachment id="…"/>` placeholders rendered as cards. */
export function MessageContent({ text }: { readonly text: string | undefined }) {
  const segments = splitRenderAttachments(text);
  if (segments.length === 0) return null;
  return (
    <>
      {segments.map((s, i) =>
        s.kind === "markdown" ? <Markdown key={i} text={s.text} /> : <InlineAttachment key={i} id={s.id} />,
      )}
    </>
  );
}

export function AttachmentRefs({ refs }: { readonly refs: unknown }) {
  const list = asArray(refs).filter(isRecord);
  if (list.length === 0) return null;
  return (
    <div className="azd-chips azd-msg-refs">
      {list.map((r, i) => {
        const id = asString(r.attachment_id) ?? asString(r.id);
        if (!id) return null;
        const op = asString(r.operation);
        const version = asString(r.version);
        return (
          <AttachmentChip
            key={`${id}-${i}`}
            id={id}
            prefix={op ? humanize(op) : undefined}
            suffix={version ? `v${version}` : undefined}
          />
        );
      })}
    </div>
  );
}

// ─── Tool calls ──────────────────────────────────────────────────────────

const ESQL_ROW_PREVIEW = 10;

function cell(value: unknown): string {
  if (value === null || value === undefined) return "";
  return typeof value === "object" ? safeJson(value, 0) : String(value);
}

function EsqlResults({ data }: { readonly data: unknown }) {
  const [all, setAll] = useState(false);
  const d = isRecord(data) ? data : {};
  const columns = asArray(d.columns).map((c) => (isRecord(c) ? asString(c.name) ?? "?" : String(c)));
  const rows = asArray(d.values).map((r) => asArray(r));
  const visible = all ? rows : rows.slice(0, ESQL_ROW_PREVIEW);
  const query = asString(d.query);
  return (
    <div className="azd-esql">
      {query && (
        <Collapsible title="ES|QL query" actions={<CopyButton text={query} label="ES|QL query" />}>
          <CodeBlock code={query} label="ES|QL query" />
        </Collapsible>
      )}
      <div className="azd-esql-caption">
        {rows.length} row{rows.length === 1 ? "" : "s"} · {columns.length} column{columns.length === 1 ? "" : "s"}
      </div>
      {columns.length > 0 && (
        <div className="azd-table-wrap">
          <table className="azd-table azd-esql-table">
            <thead>
              <tr>
                {columns.map((c, i) => (
                  <th key={`${c}-${i}`}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((r, ri) => (
                <tr key={ri}>
                  {columns.map((_, ci) => (
                    <td key={ci} title={cell(r[ci])}>
                      {truncateText(cell(r[ci]), 120)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > ESQL_ROW_PREVIEW && (
        <button type="button" className="azd-link-btn" onClick={() => setAll((a) => !a)}>
          {all ? "Show fewer rows" : `Show all ${rows.length} rows`}
        </button>
      )}
      {Object.keys(d).some((k) => !["columns", "values", "query", "source"].includes(k)) && (
        <Collapsible title="Other result fields">
          <KeyValueTree entries={Object.entries(d).filter(([k]) => !["columns", "values", "query"].includes(k))} />
        </Collapsible>
      )}
    </div>
  );
}

function ToolResultView({ result }: { readonly result: ToolResult }) {
  const d = isRecord(result.data) ? result.data : undefined;
  switch (result.type) {
    case "esql_results":
    case "tabular_data":
      return <EsqlResults data={result.data} />;
    case "query": {
      const esql = d ? asString(d.esql) : undefined;
      return esql ? (
        <div className="azd-tool-result">
          <div className="azd-subhead">Generated query</div>
          <CodeBlock code={esql} label="query" />
        </div>
      ) : (
        <Collapsible title="Query result">
          <JsonBlock value={result.data} />
        </Collapsible>
      );
    }
    case "error":
      return (
        <div className="azd-tool-error" role="alert">
          {(d && asString(d.message)) ?? (typeof result.data === "string" ? result.data : safeJson(result.data))}
          {d && Object.keys(d).some((k) => k !== "message") && (
            <KeyValueTree entries={Object.entries(d).filter(([k]) => k !== "message")} />
          )}
        </div>
      );
    default: {
      const size = safeJson(result.data).length;
      return (
        <Collapsible
          title={`${humanize(result.type || "result")} result`}
          className="azd-tool-result"
          actions={<span className="azd-muted azd-small">{size.toLocaleString()} chars</span>}
        >
          <JsonBlock value={result.data} maxChars={2000} label="tool result JSON" />
        </Collapsible>
      );
    }
  }
}

function paramPreview(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  return truncateText(
    Object.entries(params)
      .map(([k, v]) => `${k}: ${typeof v === "string" ? v : safeJson(v, 0)}`)
      .join(", "),
    90,
  );
}

const TOOL_CALL_KNOWN = ["type", "tool_id", "params", "results"];

function ToolCallCard({ step }: { readonly step: RoundStep }) {
  const results = step.results ?? [];
  const errors = results.filter((r) => r.type === "error").length;
  const params = isRecord(step.params) ? step.params : undefined;
  const details = Object.entries(step).filter(([k, v]) => !TOOL_CALL_KNOWN.includes(k) && v !== undefined);
  return (
    <div className={classNames("azd-tool", { "is-error": errors > 0 })}>
      <div className="azd-tool-head">
        <ToolIcon />
        <code className="azd-tool-id">{step.tool_id ?? "tool"}</code>
        {params && Object.keys(params).length > 0 && <span className="azd-tool-params">{paramPreview(params)}</span>}
        <span className="azd-tool-badges">
          {errors > 0 && <Badge tone="danger">error</Badge>}
          <span className="azd-muted azd-small">
            {results.length} result{results.length === 1 ? "" : "s"}
          </span>
        </span>
      </div>
      {params && Object.keys(params).length > 0 && (
        <Collapsible title="Parameters" count={Object.keys(params).length}>
          <JsonBlock value={params} label="parameters JSON" />
        </Collapsible>
      )}
      {results.map((r, i) => (
        <ToolResultView key={r.tool_result_id ?? i} result={r} />
      ))}
      {details.length > 0 && (
        <Collapsible title="Call details">
          <KeyValueTree entries={details} />
        </Collapsible>
      )}
    </div>
  );
}

// ─── Other steps ─────────────────────────────────────────────────────────

function InlineExtras({ entries }: { readonly entries: readonly (readonly [string, unknown])[] }) {
  const scalars = entries.filter(([, v]) => v === null || typeof v !== "object");
  const nested = entries.filter(([, v]) => v !== null && typeof v === "object");
  return (
    <>
      {scalars.map(([k, v]) => (
        <span key={k} className="azd-muted azd-small">
          {k}: {String(v)}
        </span>
      ))}
      {nested.length > 0 && <KeyValueTree entries={nested} />}
    </>
  );
}

function OtherStep({ step }: { readonly step: RoundStep }) {
  const rest = (known: string[]) => Object.entries(step).filter(([k]) => !known.includes(k));
  if (step.type === "relevant_skills") {
    const skills = asArray(step.skills).filter(isRecord);
    return (
      <div className="azd-step-row">
        <span className="azd-step-label">Relevant skills</span>
        <span className="azd-chips">
          {skills.map((s, i) => (
            <span key={i} className="az-chip azd-chip--sans" title={asString(s.description) ?? asString(s.path)}>
              {asString(s.name) ?? asString(s.id)}
            </span>
          ))}
        </span>
        <InlineExtras entries={rest(["type", "skills"])} />
        <Collapsible title="Skill details" count={skills.length}>
          <JsonBlock value={skills} />
        </Collapsible>
      </div>
    );
  }
  if (step.type === "substitution") {
    const n = asArray(step.substituted_tool_calls).length;
    return (
      <div className="azd-step-row">
        <span className="azd-step-label">Context compaction</span>
        <span className="azd-muted">
          {n} earlier tool result{n === 1 ? "" : "s"} replaced by references
          {asString(step.trigger) ? ` (${asString(step.trigger)})` : ""}
        </span>
        <Collapsible title="Details">
          <KeyValueTree entries={rest(["type"])} />
        </Collapsible>
      </div>
    );
  }
  const todos = asArray(step.todos ?? step.items).filter(isRecord);
  if (step.type === "update_todos" && todos.length > 0) {
    return (
      <div className="azd-step-row">
        <span className="azd-step-label">Plan</span>
        <ul className="azd-todos">
          {todos.map((t, i) => {
            const status = asString(t.status) ?? "";
            return (
              <li key={i} className={`is-${status}`}>
                <span className="azd-todo-box" aria-hidden="true">{/complete|done/i.test(status) ? "✓" : ""}</span>
                {asString(t.content) ?? asString(t.title) ?? safeJson(t, 0)}
                {status && <span className="azd-muted"> · {humanize(status)}</span>}
              </li>
            );
          })}
        </ul>
      </div>
    );
  }
  return (
    <div className="azd-step-row">
      <span className="azd-step-label">{humanize(step.type || "step")}</span>
      <ValueTree value={Object.fromEntries(rest(["type"]))} openDepth={1} />
    </div>
  );
}

type StepGroup = { readonly kind: "thinking"; readonly steps: RoundStep[] } | { readonly kind: "step"; readonly step: RoundStep };

function groupSteps(steps: readonly RoundStep[]): StepGroup[] {
  const out: StepGroup[] = [];
  for (const step of steps) {
    const last = out[out.length - 1];
    if (step.type === "reasoning") {
      if (last?.kind === "thinking") last.steps.push(step);
      else out.push({ kind: "thinking", steps: [step] });
    } else {
      out.push({ kind: "step", step });
    }
  }
  return out;
}

function Thinking({ steps }: { readonly steps: readonly RoundStep[] }) {
  const first = asString(steps[0]?.reasoning) ?? "";
  return (
    <Collapsible
      className="azd-thinking"
      title={
        <>
          <ThinkIcon /> Thinking <span className="azd-thinking-preview">{truncateText(first.replace(/\s+/g, " "), 80)}</span>
        </>
      }
      count={steps.length > 1 ? steps.length : undefined}
    >
      <ol className="azd-thinking-list">
        {steps.map((s, i) => (
          <li key={i}>
            <Markdown text={asString(s.reasoning)} />
          </li>
        ))}
      </ol>
    </Collapsible>
  );
}

export function StepView({ step }: { readonly step: RoundStep }) {
  if (step.type === "tool_call") return <ToolCallCard step={step} />;
  if (step.type === "reasoning") return <Thinking steps={[step]} />;
  return <OtherStep step={step} />;
}

export function StepsView({ steps }: { readonly steps: readonly RoundStep[] | undefined }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div className="azd-steps">
      {groupSteps(steps).map((g, i) =>
        g.kind === "thinking" ? <Thinking key={i} steps={g.steps} /> : <StepView key={i} step={g.step} />,
      )}
    </div>
  );
}

// ─── Usage + interruption ────────────────────────────────────────────────

export function usageSummary(usage: Record<string, unknown> | undefined, durationMs?: unknown): string[] {
  const u = usage ?? {};
  const cached = formatNumber(u.cached_input_tokens);
  return [
    asString(u.model),
    formatNumber(u.llm_calls) ? `${formatNumber(u.llm_calls)} LLM call${u.llm_calls === 1 ? "" : "s"}` : undefined,
    formatNumber(u.input_tokens) ? `${formatNumber(u.input_tokens)} in${cached ? ` (${cached} cached)` : ""}` : undefined,
    formatNumber(u.output_tokens) ? `${formatNumber(u.output_tokens)} out` : undefined,
    formatDuration(durationMs),
  ].filter((p): p is string => Boolean(p));
}

function interruptionMessage(interruption: unknown): { title: string; message?: string; danger: boolean } {
  const i = isRecord(interruption) ? interruption : {};
  const type = asString(i.type) ?? "interrupted";
  const err = isRecord(i.error) ? i.error : undefined;
  const by = isRecord(i.aborted_by) ? asString(i.aborted_by.source) : undefined;
  return {
    title: type === "aborted" ? `Run aborted${by ? ` by ${by}` : ""}` : type === "failed" ? "Run failed" : `Run ${humanize(type).toLowerCase()}`,
    message: err ? asString(err.message) : undefined,
    danger: type === "failed",
  };
}

export function InterruptionCallout({ interruption }: { readonly interruption: unknown }) {
  const info = interruptionMessage(interruption);
  return (
    <Callout tone={info.danger ? "danger" : "warning"} title={info.title}>
      {info.message && <div>{info.message}</div>}
      <Collapsible title="Details">
        <ValueTree value={interruption} openDepth={2} />
      </Collapsible>
    </Callout>
  );
}

// ─── Round ───────────────────────────────────────────────────────────────

export function RoundView({ item, agentId }: { readonly item: Extract<TimelineItem, { kind: "round" }>; readonly agentId?: string }) {
  const r: ConversationRound = item.round;
  const author = isRecord(r.author) ? asString(r.author.username) ?? asString(r.author.id) : undefined;
  const usage = usageSummary(r.model_usage, r.time_to_last_token);
  const runDetails = Object.entries({
    id: r.id,
    status: r.status,
    model_usage: r.model_usage,
    time_to_first_token: r.time_to_first_token,
    time_to_last_token: r.time_to_last_token,
    trace_id: r.trace_id,
    author: r.author,
  }).filter(([, v]) => v !== undefined);
  const knownRoundKeys = ["id", "status", "input", "steps", "response", "started_at", "author", "model_usage", "time_to_first_token", "time_to_last_token", "trace_id", "interruption"];
  const extraRound = Object.entries(r).filter(([k, v]) => !knownRoundKeys.includes(k) && v !== undefined);
  const extraInput = isRecord(r.input) ? Object.entries(r.input).filter(([k, v]) => !["message", "attachment_refs"].includes(k) && !(Array.isArray(v) && v.length === 0)) : [];
  return (
    <div className="azd-round">
      {r.input?.message !== undefined && (
        <div className="azd-msg azd-msg--user">
          <Avatar name={author ?? "User"} />
          <div className="azd-msg-main">
            <div className="azd-msg-head">
              <strong>{author ?? "User"}</strong>
              <span className="azd-muted">asked</span>
            </div>
            <div className="azd-msg-bubble">
              <MessageContent text={r.input.message} />
            </div>
            <AttachmentRefs refs={r.input.attachment_refs} />
            {extraInput.length > 0 && (
              <Collapsible title="Message context" count={extraInput.length}>
                <KeyValueTree entries={extraInput} />
              </Collapsible>
            )}
          </div>
        </div>
      )}
      <StepsView steps={r.steps} />
      {r.interruption !== undefined && r.interruption !== null && <InterruptionCallout interruption={r.interruption} />}
      {(r.response?.message || r.response?.structured_output !== undefined) && (
        <div className="azd-msg azd-msg--bot">
          <Avatar name="Agent" bot />
          <div className="azd-msg-main">
            <div className="azd-msg-head">
              <strong>Agent</strong>
              {agentId && <span className="azd-muted">{agentId}</span>}
            </div>
            {r.response?.message && (
              <div className="azd-msg-bubble">
                <MessageContent text={r.response.message} />
              </div>
            )}
            {r.response?.structured_output !== undefined && (
              <Collapsible title="Structured output">
                <JsonBlock value={r.response.structured_output} />
              </Collapsible>
            )}
          </div>
        </div>
      )}
      <div className="azd-round-foot">
        {r.status && <Badge tone={r.status === "completed" ? "hollow" : "warning"}>{r.status}</Badge>}
        {usage.length > 0 && <span>{usage.join(" · ")}</span>}
        {r.time_to_first_token !== undefined && <span>first token {formatDuration(r.time_to_first_token)}</span>}
      </div>
      <div className="azd-round-extras">
        <Collapsible title="Run details">
          <KeyValueTree entries={[...runDetails, ...extraRound]} openDepth={2} />
        </Collapsible>
        {item.coveredEvents.length > 0 && (
          <Collapsible title="Execution events" count={item.coveredEvents.length}>
            <JsonBlock value={item.coveredEvents} maxChars={4000} label="execution events JSON" />
          </Collapsible>
        )}
      </div>
    </div>
  );
}

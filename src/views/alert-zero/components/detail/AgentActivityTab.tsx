/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo, useState } from "react";
import classNames from "classnames";
import { EmptyState, ErrorBoundary, LoadingState } from "../../../../shared/components";
import type { AlertZeroInvestigation, ConversationEvent, RoundStep } from "../../../../shared/alert-zero-types";
import { useDetailContext } from "./DetailContext";
import { PROPOSAL_ATTACHMENT_TYPE, attachmentTypeLabel, proposalIdOfAttachment } from "./attachments";
import {
  asArray,
  asString,
  formatTime,
  humanize,
  isRecord,
  isWorkerActor,
  parseTime,
  sentenceCase,
  severityTone,
  userLabel,
} from "./helpers";
import { BotIcon, CodeIcon, DotIcon, PaperclipIcon } from "./icons";
import {
  Avatar,
  Badge,
  Callout,
  ClampedMarkdown,
  ExtraKeys,
  Field,
  Fields,
  IdValue,
  JsonBlock,
  Markdown,
  ValueTree,
} from "./primitives";
import { ProposalRef } from "./ProposalRow";
import { AttachmentChip, AttachmentRefs, MessageContent, RoundView, StepView, usageSummary } from "./RoundView";
import type { TimelineItem } from "./timeline";

export interface AgentActivityTabProps {
  readonly investigation?: AlertZeroInvestigation;
  readonly timeline: readonly TimelineItem[];
  readonly loading: boolean;
  readonly error?: string;
  readonly onRetry: () => void;
}

const KNOWN_META = ["status", "severity", "assignees", "verdict", "summary", "description", "close_reason", "workflow_execution_ids"];

function InvestigationCard({ investigation }: { readonly investigation: AlertZeroInvestigation }) {
  const c = investigation.conversation;
  const m = c.metadata ?? {};
  const resolved = new Map(investigation.assignees.map((a) => [a.uid, a]));
  const assigneeUids = m.assignees ?? investigation.assignees.map((a) => a.uid);
  const runs = m.workflow_execution_ids ?? [];
  const status = asString(m.status);
  return (
    <section className="azd-inv-card" aria-label="Investigation">
      <div className="azd-inv-head">
        <span className="azd-eyebrow">Investigation</span>
        {status && <Badge tone={status === "open" ? "primary" : "default"}>{sentenceCase(status)}</Badge>}
        {asString(m.severity) && <Badge tone={severityTone(asString(m.severity))}>{asString(m.severity)}</Badge>}
      </div>
      <div className="azd-inv-title">{c.title || "Untitled investigation"}</div>
      <Fields>
        <Field label="Assignees">
          {assigneeUids.length === 0 ? (
            <span className="azd-muted">Unassigned</span>
          ) : (
            <span className="azd-chips">
              {assigneeUids.map((uid) => (
                <span key={uid} className="az-chip azd-chip--sans" title={uid}>
                  {resolved.has(uid) ? userLabel(resolved.get(uid)) : uid}
                </span>
              ))}
            </span>
          )}
        </Field>
        <Field label="Summary">{m.summary && <Markdown text={m.summary} />}</Field>
        <Field label="Description">{m.description && <Markdown text={m.description} />}</Field>
        <Field label="Verdict">{m.verdict && <ClampedMarkdown text={m.verdict} threshold={600} />}</Field>
        <Field label="Close reason">{m.close_reason}</Field>
        <Field label="Workflow runs">
          {runs.length > 0 && (
            <ul className="azd-id-list">
              {runs.map((id) => (
                <li key={id}>
                  <IdValue value={id} label="workflow execution id" />
                </li>
              ))}
            </ul>
          )}
        </Field>
      </Fields>
      <ExtraKeys obj={m} known={KNOWN_META} title="Other metadata" />
    </section>
  );
}

function useRaw(value: unknown): [React.ReactNode, React.ReactNode] {
  const [open, setOpen] = useState(false);
  const button = (
    <button
      type="button"
      className={classNames("azd-icon-btn azd-raw-btn", { "is-active": open })}
      aria-label={open ? "Hide raw event" : "Show raw event"}
      aria-pressed={open}
      title="Raw event JSON"
      onClick={() => setOpen((o) => !o)}
    >
      <CodeIcon />
    </button>
  );
  return [button, open ? <JsonBlock value={value} label="event JSON" /> : null];
}

function TimeLabel({ iso }: { readonly iso?: string }) {
  if (!iso) return null;
  return (
    <time className="azd-tl-time" dateTime={iso} title={iso}>
      {formatTime(iso)}
    </time>
  );
}

function actorName(actor: ConversationEvent["actor"]): string {
  return asString(actor?.username) ?? asString(actor?.name) ?? asString(actor?.id) ?? "Unknown";
}

function UserMessage({ event }: { readonly event: ConversationEvent }) {
  const [rawBtn, raw] = useRaw(event);
  const data = isRecord(event.data) ? event.data : {};
  const worker = isWorkerActor(event.actor);
  const name = actorName(event.actor);
  return (
    <div className={classNames("azd-msg", worker ? "azd-msg--bot" : "azd-msg--user")}>
      <Avatar name={name} bot={worker} />
      <div className="azd-msg-main">
        <div className="azd-msg-head">
          <strong>{worker ? "Worker" : name}</strong>
          {worker && <span className="azd-muted">{name}</span>}
          <TimeLabel iso={event.created_at} />
          {rawBtn}
        </div>
        <div className="azd-msg-bubble">
          <MessageContent text={asString(data.message)} />
        </div>
        <AttachmentRefs refs={data.attachment_refs} />
        <AttachmentRefs refs={data.attachments} />
        <ExtraKeys obj={data} known={["message", "attachment_refs", "attachments"]} title="Other message fields" />
        {raw}
      </div>
    </div>
  );
}

const ATTACHMENT_VERB: Record<string, string> = {
  attachment_added: "Added",
  attachment_updated: "Updated",
  attachment_deleted: "Removed",
};

function AttachmentEvent({ event }: { readonly event: ConversationEvent }) {
  const { attachmentsById } = useDetailContext();
  const [rawBtn, raw] = useRaw(event);
  const data = isRecord(event.data) ? event.data : {};
  const id = asString(data.attachment_id) ?? "";
  const attachment = attachmentsById.get(id);
  const type = asString(data.attachment_type) ?? attachment?.type ?? "attachment";
  const verb = ATTACHMENT_VERB[event.type] ?? humanize(event.type);
  const byAgent = event.actor?.type === "agent";
  const meta = [
    asString(data.current_version) ? `v${asString(data.current_version)}` : undefined,
    asString(data.source) ? `via ${asString(data.source)}` : undefined,
    byAgent ? `by ${actorName(event.actor)}` : undefined,
  ].filter(Boolean);
  const proposalId = type === PROPOSAL_ATTACHMENT_TYPE && attachment ? proposalIdOfAttachment(attachment) : undefined;
  return (
    <div className={classNames("azd-sys", { "is-removed": event.type === "attachment_deleted" })}>
      <span className="azd-sys-icon">
        <PaperclipIcon />
      </span>
      <div className="azd-sys-main">
        <div className="azd-sys-head">
          {type === PROPOSAL_ATTACHMENT_TYPE ? (
            <span>
              {event.type === "attachment_added" ? "Proposed an action" : `${verb} a proposal`}
            </span>
          ) : id ? (
            <AttachmentChip id={id} prefix={verb} />
          ) : (
            <span>
              {verb} {attachmentTypeLabel(type)}
            </span>
          )}
          {meta.length > 0 && <span className="azd-muted azd-small">{meta.join(" · ")}</span>}
          <TimeLabel iso={event.created_at} />
          {rawBtn}
        </div>
        {type === PROPOSAL_ATTACHMENT_TYPE &&
          (proposalId ? <ProposalRef id={proposalId} /> : id && <AttachmentChip id={id} prefix={verb} />)}
        <ExtraKeys
          obj={data}
          known={["attachment_id", "attachment_type", "current_version", "source", "render_inline"]}
          title="Other fields"
        />
        {raw}
      </div>
    </div>
  );
}

function ExecutionEvent({ event }: { readonly event: ConversationEvent }) {
  const [rawBtn, raw] = useRaw(event);
  const data = isRecord(event.data) ? event.data : {};
  const usage = usageSummary(isRecord(data.model_usage) ? data.model_usage : undefined, data.time_to_last_token);
  const err = isRecord(data.error) ? data.error : undefined;
  let title: string;
  let tone: "default" | "danger" | "warning" = "default";
  switch (event.type) {
    case "execution_started":
      title = `Agent run started${asString(data.trigger_type) ? ` (trigger: ${humanize(asString(data.trigger_type) as string).toLowerCase()})` : ""}`;
      break;
    case "execution_step":
      title = "Agent step";
      break;
    case "execution_terminated":
      title = "Agent run finished";
      break;
    case "execution_failed":
      title = `Agent run failed${err && asString(err.message) ? `: ${asString(err.message)}` : ""}`;
      tone = "danger";
      break;
    case "execution_aborted": {
      const by = isRecord(data.aborted_by) ? asString(data.aborted_by.source) : undefined;
      title = `Agent run aborted${by ? ` by ${by}` : ""}`;
      tone = "danger";
      break;
    }
    default:
      title = humanize(event.type);
  }
  const step =
    event.type === "execution_step" && isRecord(data.step) && typeof data.step.type === "string"
      ? (data.step as unknown as RoundStep)
      : undefined;
  return (
    <div className={classNames("azd-sys", `azd-sys--${tone}`)}>
      <span className="azd-sys-icon">
        <BotIcon />
      </span>
      <div className="azd-sys-main">
        <div className="azd-sys-head">
          <span>{title}</span>
          {usage.length > 0 && <span className="azd-muted azd-small">{usage.join(" · ")}</span>}
          <TimeLabel iso={event.created_at} />
          {rawBtn}
        </div>
        {step && <StepView step={step} />}
        <ExtraKeys
          obj={data}
          known={["trigger_type", "model_usage", "time_to_last_token", ...(step ? ["step"] : []), ...(err ? ["error"] : []), "aborted_by"]}
          title="Details"
        />
        {raw}
      </div>
    </div>
  );
}

function GenericEvent({ event }: { readonly event: ConversationEvent }) {
  const [rawBtn, raw] = useRaw(event);
  const data = isRecord(event.data) ? event.data : {};
  const text = asString(data.message) ?? asString(data.response) ?? asString(data.text);
  return (
    <div className="azd-sys">
      <span className="azd-sys-icon">
        <DotIcon />
      </span>
      <div className="azd-sys-main">
        <div className="azd-sys-head">
          <span>{humanize(event.type || "event")}</span>
          {event.actor && <span className="azd-muted azd-small">by {actorName(event.actor)}</span>}
          <TimeLabel iso={event.created_at} />
          {rawBtn}
        </div>
        {text && <Markdown text={text} />}
        {Object.keys(data).length > 0 && (
          <ValueTree value={Object.fromEntries(Object.entries(data).filter(([, v]) => v !== text))} openDepth={1} />
        )}
        {raw}
      </div>
    </div>
  );
}

function EventView({ event }: { readonly event: ConversationEvent }) {
  if (event.type === "user_message") return <UserMessage event={event} />;
  if (event.type in ATTACHMENT_VERB) return <AttachmentEvent event={event} />;
  if (event.type.startsWith("execution_")) return <ExecutionEvent event={event} />;
  return <GenericEvent event={event} />;
}

function dayKey(iso: string | undefined): string | undefined {
  const t = parseTime(iso);
  return t === undefined ? undefined : new Date(t).toDateString();
}

function dayLabel(iso: string | undefined): string {
  const t = parseTime(iso);
  return t === undefined ? "Undated" : new Date(t).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
}

export function AgentActivityTab({ investigation, timeline, loading, error, onRetry }: AgentActivityTabProps) {
  const [newestFirst, setNewestFirst] = useState(false);
  const ordered = useMemo(() => (newestFirst ? [...timeline].reverse() : timeline), [timeline, newestFirst]);

  if (!investigation) {
    if (loading) return <LoadingState>Loading agent activity…</LoadingState>;
    return (
      <Callout tone="danger" title="Couldn't load the investigation">
        <div>{error ?? "Unknown error"}</div>
        <button type="button" className="azd-btn azd-btn--sm" onClick={onRetry}>
          Retry
        </button>
      </Callout>
    );
  }

  const agentId = investigation.conversation.agent_id;
  let lastDay: string | undefined;
  return (
    <div className="azd-tab-body">
      {error && (
        <Callout tone="warning" title="Showing the last loaded investigation">
          {error}
        </Callout>
      )}
      <InvestigationCard investigation={investigation} />
      <div className="azd-timeline-bar">
        <h3 className="azd-section-title">Timeline</h3>
        <span className="azd-count">{timeline.length}</span>
        {timeline.length > 1 && (
          <button type="button" className="azd-btn azd-btn--sm azd-btn--ghost" onClick={() => setNewestFirst((v) => !v)}>
            {newestFirst ? "Newest first" : "Oldest first"}
          </button>
        )}
      </div>
      {timeline.length === 0 ? (
        <EmptyState>No agent activity recorded on this investigation yet.</EmptyState>
      ) : (
        <ol className="azd-timeline">
          {ordered.map((item) => {
            const day = dayKey(item.at);
            const showDay = day !== lastDay;
            lastDay = day;
            return (
              <React.Fragment key={item.key}>
                {showDay && (
                  <li className="azd-tl-day" aria-hidden="true">
                    <span>{dayLabel(item.at)}</span>
                  </li>
                )}
                <li className={classNames("azd-tl-item", `azd-tl-item--${item.kind}`)}>
                  <ErrorBoundary fallback={<JsonBlock value={item.kind === "round" ? item.round : item.event} />}>
                    {item.kind === "round" ? (
                      <RoundView item={item} agentId={agentId} />
                    ) : (
                      <EventView event={item.event} />
                    )}
                  </ErrorBoundary>
                </li>
              </React.Fragment>
            );
          })}
        </ol>
      )}
      {asArray(investigation.conversation.rounds).length === 0 && timeline.length > 0 && (
        <div className="azd-muted azd-small azd-tl-note">
          Worker-driven investigation — no chat rounds yet. Follow up in Agent Builder to ask questions.
        </div>
      )}
    </div>
  );
}

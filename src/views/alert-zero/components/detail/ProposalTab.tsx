/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import {
  DISMISS_REASON_LABELS,
  type AlertZeroInvestigation,
  type AlertZeroProposalDetail,
  type DismissReason,
  type ProposalActionMetadata,
  type ResolvedUser,
} from "../../../../shared/alert-zero-types";
import { ActionInputView, RuleContextView, impactEntities } from "./ActionInputView";
import { getUnmappedFields } from "./fieldCoverage";
import { getPhaseMeta, humanize, safeJson, sentenceCase, userLabel, type BadgeTone } from "./helpers";
import {
  Badge,
  Callout,
  ClampedMarkdown,
  Collapsible,
  CopyButton,
  DateValue,
  EntityChip,
  ExtraKeys,
  Field,
  Fields,
  IdValue,
  JsonBlock,
  Markdown,
  Section,
} from "./primitives";
import { ProposalRef, ProposalRow, UserValue } from "./ProposalRow";

type DetailProposal = AlertZeroProposalDetail["proposal"];

export interface ProposalTabProps {
  readonly detail: AlertZeroProposalDetail;
  readonly investigation?: AlertZeroInvestigation;
  readonly assignees: readonly ResolvedUser[];
  readonly onShowAllFields: () => void;
}

const OUTCOME_TONE: Record<string, BadgeTone> = {
  applied: "success",
  failed: "danger",
  expired: "warning",
  applying: "primary",
};

function hasOutcomeFields(p: DetailProposal): boolean {
  return Boolean(
    p.decision || p.decidedBy || p.decidedAt || p.dismissReason || p.rationale || p.executionError || p.supersededBy,
  );
}

function OutcomeBanner({ proposal: p }: { readonly proposal: DetailProposal }) {
  const meta = getPhaseMeta(p);
  if (meta.phase === "needs_review" && !hasOutcomeFields(p)) return null;
  const tone = OUTCOME_TONE[meta.phase] ?? "default";
  const reason = p.dismissReason
    ? (DISMISS_REASON_LABELS[p.dismissReason as DismissReason] ?? humanize(p.dismissReason))
    : undefined;
  return (
    <div className={`azd-outcome azd-outcome--${tone}`} data-section="Outcome" role="status">
      <div className="azd-outcome-title">{meta.banner ?? meta.label}</div>
      {meta.hint && <div className="azd-outcome-hint">{meta.hint}</div>}
      <Fields>
        <Field label="Decision">{p.decision && (p.decision === "dismissed" ? "Declined" : humanize(p.decision))}</Field>
        <Field label="Decided by">{p.decidedBy && <UserValue user={p.decidedBy} />}</Field>
        <Field label="Decided at">{p.decidedAt && <DateValue iso={p.decidedAt} />}</Field>
        <Field label="Decline reason">{reason}</Field>
        <Field label="Rationale">{p.rationale && <Markdown text={p.rationale} />}</Field>
        <Field label="Execution error">{p.executionError && <pre className="azd-error-text">{p.executionError}</pre>}</Field>
        <Field label="Superseded by">{p.supersededBy && <ProposalRef id={p.supersededBy} />}</Field>
      </Fields>
    </div>
  );
}

const POLICY_LABEL: Record<NonNullable<ProposalActionMetadata["approvalPolicy"]>, string> = {
  "always-gate": "Always needs approval",
  "autonomy-dependent": "Approval depends on autonomy",
};

function impactTone(impact: string | undefined): BadgeTone {
  if (impact === "high" || impact === "critical") return "danger";
  if (impact === "medium") return "warning";
  return "hollow";
}

const KNOWN_ACTION_KEYS = ["name", "description", "category", "impact", "reversible", "approvalPolicy"];

function WhatHappens({ detail, investigation }: { readonly detail: AlertZeroProposalDetail; readonly investigation?: AlertZeroInvestigation }) {
  const p = detail.proposal;
  const action = p.action;
  const inputJson = safeJson(p.actionInput ?? {});
  return (
    <Section title="What happens if you approve" section="What happens if you approve">
      <div className="azd-action-card">
        <div className="azd-action-head">
          <div className="azd-action-name">
            {action?.name ?? (p.actionWorkflowId ? humanize(p.actionWorkflowId.replace(/^system-alertzero-action-/, "")) : "No automated action")}
          </div>
          <div className="azd-badges">
            {action?.category && <Badge tone="hollow">{sentenceCase(action.category)}</Badge>}
            {action?.impact && <Badge tone={impactTone(action.impact)}>{sentenceCase(action.impact)} impact</Badge>}
            {action?.reversible !== undefined && (
              <Badge tone={action.reversible ? "success" : "warning"}>{action.reversible ? "Reversible" : "Irreversible"}</Badge>
            )}
            {action?.approvalPolicy && (
              <Badge tone="hollow" title={`approvalPolicy: ${action.approvalPolicy}`}>
                {POLICY_LABEL[action.approvalPolicy] ?? action.approvalPolicy}
              </Badge>
            )}
          </div>
        </div>
        {action?.description && <p className="azd-action-desc">{action.description}</p>}
        <ExtraKeys obj={action as Record<string, unknown> | undefined} known={KNOWN_ACTION_KEYS} title="Other action metadata" />
        {p.actionWorkflowId ? (
          <ActionInputView
            actionWorkflowId={p.actionWorkflowId}
            actionInput={p.actionInput}
            ruleContext={detail.ruleContext}
            investigation={investigation}
          />
        ) : (
          <div className="azd-muted">No automated action is attached — approving only records the decision.</div>
        )}
        <RuleContextView ruleContext={detail.ruleContext} />
        <Collapsible
          title="Exact input that will run"
          actions={<CopyButton text={inputJson} label="action input JSON" />}
        >
          <JsonBlock value={p.actionInput ?? {}} label="action input JSON" />
        </Collapsible>
        {p.actionWorkflowId && (
          <div className="azd-action-workflow">
            <span className="azd-muted">Action workflow</span>
            <IdValue value={p.actionWorkflowId} label="action workflow id" />
          </div>
        )}
      </div>
    </Section>
  );
}

function Lineage({ detail }: { readonly detail: AlertZeroProposalDetail }) {
  const p = detail.proposal;
  const chain = detail.revisionChain.length > 0 ? detail.revisionChain : [p];
  const show = chain.length > 1 || p.supersedes || p.supersededBy || p.rootProposalId || p.revision !== undefined;
  if (!show) return null;
  const idx = chain.findIndex((r) => r.id === p.id);
  const revision = p.revision ?? (idx >= 0 ? idx + 1 : undefined);
  return (
    <Section title="Lineage" section="Lineage">
      <div className="azd-lineage-head">
        Revision {revision ?? "?"} of {Math.max(chain.length, revision ?? 0)}
      </div>
      <ol className="azd-revisions">
        {chain.map((r, i) => (
          <li key={r.id} className={classNames({ "is-current": r.id === p.id })}>
            <ProposalRow proposal={r} label={`Rev ${r.revision ?? i + 1}`} />
          </li>
        ))}
      </ol>
      <Fields>
        <Field label="Supersedes">{p.supersedes && <IdValue value={p.supersedes} label="superseded proposal id" />}</Field>
        <Field label="Superseded by">{p.supersededBy && <IdValue value={p.supersededBy} label="newer proposal id" />}</Field>
        <Field label="Root proposal">{p.rootProposalId && <IdValue value={p.rootProposalId} label="root proposal id" />}</Field>
      </Fields>
    </Section>
  );
}

function Siblings({ detail }: { readonly detail: AlertZeroProposalDetail }) {
  return (
    <Section title="Other proposals on this investigation" count={detail.siblings.length}>
      {detail.siblings.length === 0 ? (
        <div className="azd-muted">None — this is the only proposal on the investigation.</div>
      ) : (
        <div className="azd-prow-list">
          {detail.siblings.map((s) => (
            <ProposalRow key={s.id} proposal={s} />
          ))}
        </div>
      )}
    </Section>
  );
}

function InvestigationSection({
  proposal: p,
  investigation,
  assignees,
}: {
  readonly proposal: DetailProposal;
  readonly investigation?: AlertZeroInvestigation;
  readonly assignees: readonly ResolvedUser[];
}) {
  const uids = p.conversationAssignees ?? investigation?.conversation.metadata?.assignees;
  const names = new Map(assignees.map((a) => [a.uid, a]));
  const entityNames = new Map(impactEntities(investigation).map((e) => [e.id, e.name]));
  return (
    <Section title="Investigation" section="Investigation">
      <Fields>
        <Field label="Title">{p.conversationTitle ?? investigation?.conversation.title}</Field>
        <Field label="Agent">{p.conversationAgentId && <code className="azd-mono">{p.conversationAgentId}</code>}</Field>
        <Field label="Assignees">
          {uids &&
            (uids.length === 0 ? (
              <span className="azd-muted">Unassigned</span>
            ) : (
              <span className="azd-chips">
                {uids.map((uid) => {
                  const user = names.get(uid);
                  return (
                    <span key={uid} className="az-chip azd-chip--sans" title={uid}>
                      {user ? userLabel(user) : uid}
                    </span>
                  );
                })}
              </span>
            ))}
        </Field>
        <Field label="Entities">
          {p.entityIds && p.entityIds.length > 0 && (
            <span className="azd-chips">
              {p.entityIds.map((id) => (
                <EntityChip key={id} id={id} name={entityNames.get(id)} type={id.split(":")[0]} />
              ))}
            </span>
          )}
        </Field>
      </Fields>
    </Section>
  );
}

function Provenance({ proposal: p, onShowAllFields }: { readonly proposal: DetailProposal; readonly onShowAllFields: () => void }) {
  const unknown = getUnmappedFields(p as unknown as Record<string, unknown>);
  return (
    <Section title="Provenance" section="Provenance">
      <Fields>
        <Field label="Proposal id">
          <IdValue value={p.id} label="proposal id" />
        </Field>
        <Field label="Status">
          <code className="azd-mono">{p.status}</code>
          {p.decision && <span className="azd-muted"> · decision {p.decision}</span>}
        </Field>
        <Field label="Investigation id">
          <IdValue value={p.conversationId} label="investigation id" />
        </Field>
        <Field label="Space">{p.spaceId && <code className="azd-mono">{p.spaceId}</code>}</Field>
        <Field label="Origin">{p.origin}</Field>
        <Field label="Created by">{p.createdBy && <UserValue user={p.createdBy} />}</Field>
        <Field label="Created">{p.createdAt && <DateValue iso={p.createdAt} />}</Field>
        <Field label="Expires">{p.expiresAt && <DateValue iso={p.expiresAt} />}</Field>
        <Field label="Workflow execution">
          {p.workflowExecutionId && <IdValue value={p.workflowExecutionId} label="workflow execution id" />}
        </Field>
      </Fields>
      {unknown.length > 0 && (
        <Callout tone="primary" title={`${unknown.length} field${unknown.length === 1 ? "" : "s"} this view doesn't recognise yet`}>
          <code className="azd-mono">{unknown.join(", ")}</code> —{" "}
          <button type="button" className="azd-link-btn" onClick={onShowAllFields}>
            see All fields
          </button>
        </Callout>
      )}
    </Section>
  );
}

export function ProposalTab({ detail, investigation, assignees, onShowAllFields }: ProposalTabProps) {
  const p = detail.proposal;
  return (
    <div className="azd-tab-body">
      <OutcomeBanner proposal={p} />
      {p.previousExecutionError && (
        <Callout tone="warning" title="A previous attempt at this action failed" section="Previous attempt">
          <pre className="azd-error-text">{p.previousExecutionError}</pre>
        </Callout>
      )}
      <Section title="Why" section="Why">
        {p.comment ? <ClampedMarkdown text={p.comment} threshold={1400} /> : <div className="azd-muted">No rationale provided.</div>}
      </Section>
      <WhatHappens detail={detail} investigation={investigation} />
      <Lineage detail={detail} />
      <Siblings detail={detail} />
      <InvestigationSection proposal={p} investigation={investigation} assignees={assignees} />
      <Provenance proposal={p} onShowAllFields={onShowAllFields} />
    </div>
  );
}

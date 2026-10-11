/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import {
  ACTION_WORKFLOW_IDS,
  type AlertZeroInvestigation,
  type AlertZeroProposalDetail,
} from "../../../../shared/alert-zero-types";
import { getCurrentVersion, isRemoved } from "./attachments";
import {
  asArray,
  asString,
  asStringArray,
  humanize,
  isRecord,
  safeJson,
  severityTone,
  stableJson,
} from "./helpers";
import {
  AlertList,
  Badge,
  Callout,
  ChipList,
  CodeBlock,
  Collapsible,
  CopyButton,
  EntityChip,
  ExtraKeys,
  Field,
  Fields,
  IdValue,
  KeyValueTree,
  Markdown,
  MitreThreatList,
  ScalarValue,
  ValueTree,
} from "./primitives";

type RuleContext = AlertZeroProposalDetail["ruleContext"];

export interface ActionInputViewProps {
  readonly actionWorkflowId?: string;
  readonly actionInput?: Record<string, unknown>;
  readonly ruleContext?: RuleContext;
  readonly investigation?: AlertZeroInvestigation;
}

interface ImpactEntity {
  readonly id: string;
  readonly name?: string;
  readonly type?: string;
}

/** Entities from active `investigation_impact` attachments, deduped by id. */
export function impactEntities(investigation: AlertZeroInvestigation | undefined): ImpactEntity[] {
  const out = new Map<string, ImpactEntity>();
  for (const a of investigation?.conversation.attachments ?? []) {
    if (a.type !== "investigation_impact" || isRemoved(a)) continue;
    const data = getCurrentVersion(a)?.data;
    if (!isRecord(data)) continue;
    for (const e of asArray(data.entities)) {
      if (!isRecord(e)) continue;
      const id = asString(e.id);
      if (id && !out.has(id)) out.set(id, { id, name: asString(e.name), type: asString(e.type) });
    }
  }
  return [...out.values()];
}

function EndpointList({ ids }: { readonly ids: readonly string[] }) {
  if (ids.length === 0) return <span className="azd-muted">No endpoints listed</span>;
  return (
    <ul className="azd-id-list">
      {ids.map((id) => (
        <li key={id}>
          <IdValue value={id} label="endpoint id" />
        </li>
      ))}
    </ul>
  );
}

function AffectedHosts({ investigation }: { readonly investigation?: AlertZeroInvestigation }) {
  const hosts = impactEntities(investigation).filter((e) => e.type === "host");
  if (hosts.length === 0) return null;
  return (
    <div className="azd-action-context">
      <div className="azd-subhead">Affected hosts (investigation impact)</div>
      <div className="azd-chips">
        {hosts.map((h) => (
          <EntityChip key={h.id} id={h.id} name={h.name} type="host" />
        ))}
      </div>
    </div>
  );
}

function ActionComment({ text }: { readonly text: unknown }) {
  const comment = asString(text);
  if (!comment) return null;
  return (
    <div className="azd-action-comment">
      <div className="azd-subhead">Comment recorded with the action</div>
      <blockquote className="azd-quote">{comment}</blockquote>
    </div>
  );
}

function IsolateHostInput({ input, investigation }: { readonly input: Record<string, unknown>; readonly investigation?: AlertZeroInvestigation }) {
  const ids = asStringArray(input.endpoint_ids);
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Network-isolate <strong>{ids.length}</strong> endpoint{ids.length === 1 ? "" : "s"}. Only Elastic Defend keeps connectivity.
      </div>
      <EndpointList ids={ids} />
      <AffectedHosts investigation={investigation} />
      <ActionComment text={input.comment} />
      <ExtraKeys obj={input} known={["endpoint_ids", "comment"]} />
    </div>
  );
}

function ProcessInput({
  input,
  verb,
  investigation,
}: {
  readonly input: Record<string, unknown>;
  readonly verb: "Kill" | "Suspend";
  readonly investigation?: AlertZeroInvestigation;
}) {
  const ids = asStringArray(input.endpoint_ids);
  const params = isRecord(input.parameters) ? input.parameters : {};
  const pid = asString(params.pid);
  const entityId = asString(params.entity_id);
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        {verb} {pid ? <>process <strong>pid {pid}</strong></> : entityId ? "process by entity id" : "a process"} on{" "}
        <strong>{ids.length}</strong> endpoint{ids.length === 1 ? "" : "s"}
        {params.kill_descendants === true ? ", including all descendant processes" : ""}.
      </div>
      <Fields>
        <Field label="PID">{pid && <IdValue value={pid} label="pid" />}</Field>
        <Field label="Entity id">{entityId && <IdValue value={entityId} label="process entity id" />}</Field>
        {"kill_descendants" in params && (
          <Field label="Kill descendants">
            <Badge tone={params.kill_descendants === true ? "warning" : "default"}>
              {params.kill_descendants === true ? "Yes" : "No"}
            </Badge>
          </Field>
        )}
        <Field label="Endpoints">
          <EndpointList ids={ids} />
        </Field>
      </Fields>
      <ExtraKeys obj={params} known={["pid", "entity_id", "kill_descendants"]} title="Other parameters" />
      <AffectedHosts investigation={investigation} />
      <ActionComment text={input.comment} />
      <ExtraKeys obj={input} known={["endpoint_ids", "parameters", "comment"]} />
    </div>
  );
}

function CloseAlertsInput({ input }: { readonly input: Record<string, unknown> }) {
  const ids = asStringArray(input.alertIds);
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Close <strong>{ids.length}</strong> alert{ids.length === 1 ? "" : "s"} as false positive.
      </div>
      {asString(input.reason) && (
        <Fields>
          <Field label="Reason">{asString(input.reason)}</Field>
        </Fields>
      )}
      <AlertList ids={ids} />
      <ExtraKeys obj={input} known={["alertIds", "reason"]} />
    </div>
  );
}

function DiffValue({ value, field }: { readonly value: unknown; readonly field: string }) {
  if (value === undefined) return <span className="azd-kv-null">—</span>;
  if (typeof value === "string" && (field === "query" || value.includes("\n") || value.length > 80)) {
    return <pre className="az-code az-code--wrap azd-diff-code">{value}</pre>;
  }
  if (typeof value === "object" && value !== null) {
    return <pre className="az-code az-code--wrap azd-diff-code">{safeJson(value)}</pre>;
  }
  return <ScalarValue value={value} />;
}

function RuleHeading({ id, ruleContext, idLabel = "Rule" }: { readonly id?: string; readonly ruleContext?: RuleContext; readonly idLabel?: string }) {
  const current = ruleContext?.current;
  const name = current ? asString(current.name) : undefined;
  return (
    <Fields>
      <Field label={idLabel}>
        {(name || id) && (
          <span className="azd-rule-ref">
            {name && <strong>{name}</strong>}
            {id && <IdValue value={id} label="rule id" />}
          </span>
        )}
      </Field>
    </Fields>
  );
}

function RevisionCheck({ expected, ruleContext }: { readonly expected: unknown; readonly ruleContext?: RuleContext }) {
  if (expected === undefined) return null;
  const current = ruleContext?.current?.revision;
  const mismatch = current !== undefined && String(current) !== String(expected);
  return (
    <div className={classNames("azd-revision-check", { "is-mismatch": mismatch })}>
      Expected rule revision <strong>{String(expected)}</strong>
      {current !== undefined && (
        <>
          {" "}
          · current <strong>{String(current)}</strong>
          {mismatch && " — the rule changed since this was proposed"}
        </>
      )}
    </div>
  );
}

function EditRuleInput({ input, ruleContext }: { readonly input: Record<string, unknown>; readonly ruleContext?: RuleContext }) {
  const current = ruleContext?.current;
  const fields = Object.keys(input).filter((k) => k !== "id" && k !== "expected_revision");
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Update <strong>{fields.length}</strong> field{fields.length === 1 ? "" : "s"} on a detection rule.
      </div>
      <RuleHeading id={asString(input.id)} ruleContext={ruleContext} />
      <RevisionCheck expected={input.expected_revision} ruleContext={ruleContext} />
      <div className="azd-table-wrap">
        <table className="azd-table azd-diff">
          <thead>
            <tr>
              <th>Field</th>
              <th>Current</th>
              <th>Proposed</th>
            </tr>
          </thead>
          <tbody>
            {fields.map((f) => {
              const before = current?.[f];
              const changed = !current || stableJson(before) !== stableJson(input[f]);
              return (
                <tr key={f} className={classNames({ "is-changed": changed && current })}>
                  <td className="azd-mono">{f}</td>
                  <td className="azd-diff-before">
                    {current ? <DiffValue value={before} field={f} /> : <span className="azd-kv-null">unknown</span>}
                  </td>
                  <td className="azd-diff-after">
                    <DiffValue value={input[f]} field={f} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function entryValue(entry: Record<string, unknown>): React.ReactNode {
  if (Array.isArray(entry.value)) return <ChipList values={asStringArray(entry.value)} mono />;
  if (Array.isArray(entry.values)) return <ChipList values={asStringArray(entry.values)} mono />;
  if (isRecord(entry.list)) return <span className="azd-mono">list {asString(entry.list.id)} ({asString(entry.list.type)})</span>;
  const v = asString(entry.value);
  return v !== undefined ? <code className="azd-mono">{v}</code> : <span className="azd-kv-null">—</span>;
}

function ExceptionEntryRows({ entries, depth = 0 }: { readonly entries: unknown[]; readonly depth?: number }) {
  return (
    <>
      {entries.filter(isRecord).map((e, i) => (
        <React.Fragment key={`${depth}-${i}`}>
          <tr>
            <td className="azd-mono" style={{ paddingLeft: 8 + depth * 14 }}>
              {asString(e.field) ?? "—"}
            </td>
            <td>{asString(e.operator) ?? "—"}</td>
            <td>{asString(e.type) ?? "—"}</td>
            <td>{e.type === "nested" ? <span className="azd-muted">nested</span> : entryValue(e)}</td>
          </tr>
          {Array.isArray(e.entries) && <ExceptionEntryRows entries={e.entries} depth={depth + 1} />}
        </React.Fragment>
      ))}
    </>
  );
}

function AddExceptionInput({ input, ruleContext }: { readonly input: Record<string, unknown>; readonly ruleContext?: RuleContext }) {
  const entries = asArray(input.entries);
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Add a rule exception with <strong>{entries.length}</strong> condition{entries.length === 1 ? "" : "s"}. Matching
        events will stop generating alerts.
      </div>
      <RuleHeading id={asString(input.rule_id)} ruleContext={ruleContext} />
      <RevisionCheck expected={input.expected_revision} ruleContext={ruleContext} />
      <Fields>
        <Field label="Exception name">{asString(input.name)}</Field>
        <Field label="Description">{asString(input.description)}</Field>
      </Fields>
      <div className="azd-table-wrap">
        <table className="azd-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Operator</th>
              <th>Type</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            <ExceptionEntryRows entries={entries} />
          </tbody>
        </table>
      </div>
      <ExtraKeys obj={input} known={["rule_id", "expected_revision", "name", "description", "entries"]} />
    </div>
  );
}

function ScheduleFields({ input }: { readonly input: Record<string, unknown> }) {
  return (
    <>
      <Field label="Runs every">{asString(input.interval)}</Field>
      <Field label="Look-back from">{asString(input.from)}</Field>
      <Field label="To">{asString(input.to)}</Field>
    </>
  );
}

function CreateRuleInput({ input }: { readonly input: Record<string, unknown> }) {
  const query = asString(input.query);
  const severity = asString(input.severity);
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Create a new <strong>{asString(input.type) ?? "detection"}</strong> rule
        {asString(input.name) ? <> named <strong>{asString(input.name)}</strong></> : null}.
      </div>
      <Fields>
        <Field label="Name">{asString(input.name)}</Field>
        <Field label="Description">{asString(input.description) && <Markdown text={asString(input.description)} />}</Field>
        <Field label="Severity">{severity && <Badge tone={severityTone(severity)}>{severity}</Badge>}</Field>
        <Field label="Risk score">{asString(input.risk_score)}</Field>
        <Field label="Type">
          {(asString(input.type) || asString(input.language)) &&
            [asString(input.type), asString(input.language)].filter(Boolean).join(" · ")}
        </Field>
        <ScheduleFields input={input} />
        <Field label="Tags">{asStringArray(input.tags).length > 0 && <ChipList values={asStringArray(input.tags)} />}</Field>
        <Field label="MITRE ATT&CK">{asArray(input.threat).length > 0 && <MitreThreatList threats={input.threat} />}</Field>
      </Fields>
      {query && (
        <div className="azd-action-query">
          <div className="azd-subhead">Query</div>
          <CodeBlock code={query} label="query" />
        </div>
      )}
      <ExtraKeys
        obj={input}
        known={["type", "language", "name", "description", "query", "severity", "risk_score", "interval", "from", "to", "threat", "tags"]}
      />
    </div>
  );
}

function EnableRuleInput({ input, ruleContext }: { readonly input: Record<string, unknown>; readonly ruleContext?: RuleContext }) {
  const enabled = ruleContext?.current?.enabled;
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Enable a detection rule so it starts generating alerts
        {enabled === true ? " (it is already enabled)" : enabled === false ? " (currently disabled)" : ""}.
      </div>
      <RuleHeading id={asString(input.id)} ruleContext={ruleContext} />
      <ExtraKeys obj={input} known={["id"]} />
    </div>
  );
}

function InstallPrebuiltInput({ input, ruleContext }: { readonly input: Record<string, unknown>; readonly ruleContext?: RuleContext }) {
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">Install an Elastic prebuilt detection rule.</div>
      <RuleHeading id={asString(input.rule_id)} ruleContext={ruleContext} idLabel="Prebuilt rule" />
      <Fields>
        <Field label="Version">{asString(input.version)}</Field>
      </Fields>
      <ExtraKeys obj={input} known={["rule_id", "version"]} />
    </div>
  );
}

const FORENSICS_LABELS: Record<string, string> = {
  classification: "Classification",
  attack_discovery_id: "Attack Discovery",
  investigation_id: "Investigation",
  ai_index_id: "Knowledge index",
  workflow_execution_id: "Workflow execution",
};

function ForensicsInput({ input }: { readonly input: Record<string, unknown> }) {
  const classification = asString(input.classification);
  return (
    <div className="azd-action-input">
      <div className="azd-action-lead">
        Hand this investigation off to the Endpoint Forensics Worker for deep host analysis.
      </div>
      <Fields>
        {Object.entries(FORENSICS_LABELS).map(([key, label]) => {
          const v = asString(input[key]);
          if (!v) return null;
          return (
            <Field key={key} label={label}>
              {key === "classification" && classification ? (
                <Badge tone={/true/i.test(classification) ? "danger" : "default"}>{humanize(classification)}</Badge>
              ) : (
                <IdValue value={v} label={label.toLowerCase()} />
              )}
            </Field>
          );
        })}
      </Fields>
      <ExtraKeys obj={input} known={Object.keys(FORENSICS_LABELS)} />
    </div>
  );
}

/** Live rule state for rule-editing actions (fail-soft). */
export function RuleContextView({ ruleContext }: { readonly ruleContext?: RuleContext }) {
  if (!ruleContext || (!ruleContext.current && !ruleContext.error)) return null;
  const current = ruleContext.current;
  return (
    <div className="azd-rule-context">
      {ruleContext.error && (
        <Callout tone="warning" title="Couldn't load the current rule">
          {ruleContext.error}
        </Callout>
      )}
      {current && (
        <Collapsible
          title="Current rule (live)"
          actions={<CopyButton text={safeJson(current)} label="current rule JSON" />}
        >
          <ValueTree value={current} openDepth={1} />
        </Collapsible>
      )}
    </div>
  );
}

export function ActionInputView({ actionWorkflowId, actionInput, ruleContext, investigation }: ActionInputViewProps) {
  if (!actionInput || Object.keys(actionInput).length === 0) {
    return <div className="azd-muted">This action takes no input.</div>;
  }
  switch (actionWorkflowId) {
    case ACTION_WORKFLOW_IDS.isolateHost:
      return <IsolateHostInput input={actionInput} investigation={investigation} />;
    case ACTION_WORKFLOW_IDS.killProcess:
      return <ProcessInput input={actionInput} verb="Kill" investigation={investigation} />;
    case ACTION_WORKFLOW_IDS.suspendProcess:
      return <ProcessInput input={actionInput} verb="Suspend" investigation={investigation} />;
    case ACTION_WORKFLOW_IDS.closeAlertsFp:
      return <CloseAlertsInput input={actionInput} />;
    case ACTION_WORKFLOW_IDS.editRule:
      return <EditRuleInput input={actionInput} ruleContext={ruleContext} />;
    case ACTION_WORKFLOW_IDS.addRuleException:
      return <AddExceptionInput input={actionInput} ruleContext={ruleContext} />;
    case ACTION_WORKFLOW_IDS.createRule:
      return <CreateRuleInput input={actionInput} />;
    case ACTION_WORKFLOW_IDS.enableRule:
      return <EnableRuleInput input={actionInput} ruleContext={ruleContext} />;
    case ACTION_WORKFLOW_IDS.installPrebuiltRule:
      return <InstallPrebuiltInput input={actionInput} ruleContext={ruleContext} />;
    case ACTION_WORKFLOW_IDS.handoffToForensics:
      return <ForensicsInput input={actionInput} />;
    default:
      return (
        <div className="azd-action-input">
          <KeyValueTree entries={Object.entries(actionInput)} openDepth={2} />
        </div>
      );
  }
}

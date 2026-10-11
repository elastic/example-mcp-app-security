/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from "react";
import type { ConversationAttachment } from "../../../../shared/alert-zero-types";
import { useDetailContext } from "./DetailContext";
import {
  PROPOSAL_ATTACHMENT_TYPE,
  formatDiscoveryMarkdown,
  formatDiscoveryTitle,
  iocCategories,
  iocsToCsv,
  proposalIdOfAttachment,
  toReplacementMap,
} from "./attachments";
import {
  asArray,
  asString,
  asStringArray,
  formatDateTime,
  humanize,
  isRecord,
  parseTime,
  severityTone,
  userLabel,
} from "./helpers";
import { DownloadIcon } from "./icons";
import {
  AlertList,
  Badge,
  ChipList,
  ClampedMarkdown,
  CodeBlock,
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
  MitreThreatList,
  ValueTree,
} from "./primitives";
import { ProposalRef } from "./ProposalRow";

type Data = Record<string, unknown>;

function GenericData({ data }: { readonly data: unknown }) {
  if (typeof data === "string") return <ClampedMarkdown text={data} />;
  if (data === undefined) return <div className="azd-muted">No data in this version.</div>;
  return <ValueTree value={data} openDepth={2} />;
}

// ─── Evidence items (impact, hypotheses) ─────────────────────────────────

function MiniChart({ chart }: { readonly chart: Data }) {
  const series = asArray(chart.series).filter(isRecord);
  const points = series.flatMap((s) => asArray(s.points).filter(isRecord));
  const ys = points.map((p) => (typeof p.y === "number" ? p.y : 0));
  const max = Math.max(1, ...ys);
  const min = Math.min(0, ...ys);
  const colors = ["var(--accent)", "var(--severity-high)", "var(--severity-low)", "var(--severity-medium)", "var(--text-muted)"];
  return (
    <figure className="azd-chart">
      <figcaption>
        {asString(chart.title) ?? "Chart"}
        {asString(isRecord(chart.y_axis) ? chart.y_axis.label : undefined) && (
          <span className="azd-muted"> · {asString((chart.y_axis as Data).label)}</span>
        )}
      </figcaption>
      <svg viewBox="0 0 100 30" preserveAspectRatio="none" className="azd-chart-svg" role="img" aria-label={asString(chart.title)}>
        {series.map((s, si) => {
          const pts = asArray(s.points).filter(isRecord);
          if (pts.length === 0) return null;
          const d = pts
            .map((p, i) => {
              const x = pts.length === 1 ? 50 : (i / (pts.length - 1)) * 100;
              const y = 29 - (((typeof p.y === "number" ? p.y : 0) - min) / (max - min || 1)) * 28;
              return `${x.toFixed(2)},${y.toFixed(2)}`;
            })
            .join(" ");
          return <polyline key={si} points={d} fill="none" stroke={colors[si % colors.length]} strokeWidth="1" vectorEffect="non-scaling-stroke" />;
        })}
      </svg>
      <div className="azd-chart-legend">
        {series.map((s, si) => (
          <span key={si}>
            <span className="azd-chart-swatch" style={{ background: colors[si % colors.length] }} />
            {asString(s.name)} ({asArray(s.points).length} pts)
          </span>
        ))}
      </div>
      <Collapsible title="Chart data">
        <JsonBlock value={chart} label="chart JSON" />
      </Collapsible>
    </figure>
  );
}

function EvidenceItems({ evidence }: { readonly evidence: unknown }) {
  const items = (Array.isArray(evidence) ? evidence : evidence ? [evidence] : []).filter(isRecord);
  if (items.length === 0) return null;
  return (
    <ul className="azd-evidence-items">
      {items.map((e, i) => (
        <li key={i}>
          {asString(e.description) && <Markdown text={asString(e.description)} />}
          {isRecord(e.chart) && <MiniChart chart={e.chart} />}
          <ExtraKeys obj={e} known={["description", "chart"]} title="Other evidence fields" />
        </li>
      ))}
    </ul>
  );
}

/** Investigation documents (impact, hypotheses) share these housekeeping keys. */
const RECORD_KEYS = ["id", "spaceId", "conversationId", "createdAt", "updatedAt", "createdBy"];

function RecordedLine({ data }: { readonly data: Data }) {
  const created = asString(data.createdAt);
  const updated = asString(data.updatedAt);
  const by = isRecord(data.createdBy) ? userLabel(data.createdBy) : asString(data.createdBy);
  if (!created && !updated && !by) return null;
  return (
    <div className="azd-muted azd-small">
      {created ? `Recorded ${formatDateTime(created)}` : "Recorded"}
      {by ? ` by ${by}` : ""}
      {updated && updated !== created ? ` · updated ${formatDateTime(updated)}` : ""}
    </div>
  );
}

// ─── Per-type renderers ──────────────────────────────────────────────────

function AttackDiscoveryView({ data }: { readonly data: Data }) {
  const replacements = useMemo(() => toReplacementMap(data.replacements), [data.replacements]);
  const alertIds = asStringArray(data.alert_ids);
  const tactics = asStringArray(data.mitre_attack_tactics);
  const replacementEntries = Object.entries(replacements);
  return (
    <div className="azd-ad">
      <div className="azd-ad-title">{formatDiscoveryTitle(asString(data.title), replacements)}</div>
      <div className="azd-ad-meta">
        {asString(data.timestamp) && <DateValue iso={asString(data.timestamp)} />}
        <span>{alertIds.length} alert{alertIds.length === 1 ? "" : "s"}</span>
        {asString(data.id) && <IdValue value={asString(data.id) as string} label="attack discovery id" />}
      </div>
      {tactics.length > 0 && (
        <div className="azd-chips">
          {tactics.map((t) => (
            <span key={t} className="azd-mitre-tactic">
              {t}
            </span>
          ))}
        </div>
      )}
      {asString(data.summary_markdown) && (
        <Markdown text={formatDiscoveryMarkdown(asString(data.summary_markdown), replacements)} className="azd-ad-summary" />
      )}
      {asString(data.entity_summary_markdown) && (
        <div>
          <div className="azd-subhead">Entities</div>
          <Markdown text={formatDiscoveryMarkdown(asString(data.entity_summary_markdown), replacements)} />
        </div>
      )}
      {asString(data.details_markdown) && (
        <div>
          <div className="azd-subhead">Details</div>
          <ClampedMarkdown text={formatDiscoveryMarkdown(asString(data.details_markdown), replacements)} threshold={1200} />
        </div>
      )}
      {alertIds.length > 0 && (
        <Collapsible title="Correlated alerts" count={alertIds.length}>
          <AlertList ids={alertIds} />
        </Collapsible>
      )}
      {replacementEntries.length > 0 && (
        <Collapsible title="Anonymization replacements" count={replacementEntries.length}>
          <table className="azd-table">
            <thead>
              <tr>
                <th>Token</th>
                <th>Original value</th>
              </tr>
            </thead>
            <tbody>
              {replacementEntries.map(([token, value]) => (
                <tr key={token}>
                  <td className="azd-mono">{token}</td>
                  <td>{value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Collapsible>
      )}
      <ExtraKeys
        obj={data}
        known={["title", "timestamp", "alert_ids", "id", "mitre_attack_tactics", "summary_markdown", "entity_summary_markdown", "details_markdown", "replacements"]}
        title="Other fields"
      />
    </div>
  );
}

function verdictTone(verdict: string | undefined) {
  if (!verdict) return "default" as const;
  if (/true[_ ]?positive|malicious|confirmed/i.test(verdict)) return "danger" as const;
  if (/false[_ ]?positive|benign/i.test(verdict)) return "success" as const;
  return "warning" as const;
}

function VerdictView({ data }: { readonly data: Data }) {
  const verdict = asString(data.verdict);
  return (
    <div className="azd-verdict">
      {verdict && (
        <div className="azd-verdict-head">
          <Badge tone={verdictTone(verdict)}>{humanize(verdict)}</Badge>
        </div>
      )}
      {asString(data.summary_markdown) && <Markdown text={asString(data.summary_markdown)} />}
      {asString(data.rationale_markdown) && (
        <div>
          <div className="azd-subhead">Rationale</div>
          <ClampedMarkdown text={asString(data.rationale_markdown)} threshold={1000} />
        </div>
      )}
      <ExtraKeys obj={data} known={["verdict", "summary_markdown", "rationale_markdown"]} title="Other fields" />
    </div>
  );
}

function ImpactView({ data }: { readonly data: Data }) {
  const entities = asArray(data.entities).filter(isRecord);
  return (
    <div className="azd-impact">
      {asString(data.summary) && <Markdown text={asString(data.summary)} />}
      <EvidenceItems evidence={data.evidence} />
      {entities.length > 0 && (
        <div className="azd-entity-grid">
          {entities.map((e, i) => (
            <div key={asString(e.id) ?? i} className="azd-entity-card">
              <EntityChip id={asString(e.id)} name={asString(e.name)} type={asString(e.type)} />
              {asString(e.type) && <span className="azd-muted">{humanize(asString(e.type) as string)}</span>}
              <EvidenceItems evidence={e.evidence} />
              <ExtraKeys obj={e} known={["id", "name", "type", "evidence"]} title="Other entity fields" />
            </div>
          ))}
        </div>
      )}
      <RecordedLine data={data} />
      <ExtraKeys obj={data} known={["summary", "evidence", "entities", ...RECORD_KEYS]} title="Other fields" />
    </div>
  );
}

function AlertsView({ data }: { readonly data: Data }) {
  const ids = asStringArray(data.alertIds ?? data.alert_ids);
  return (
    <div>
      <AlertList ids={ids} limit={8} />
      <ExtraKeys obj={data} known={["alertIds", "alert_ids"]} title="Other fields" />
    </div>
  );
}

function TimelineView({ data }: { readonly data: Data }) {
  const events = asArray(data.events)
    .filter(isRecord)
    .map((e, i) => ({ e, i, t: parseTime(asString(e.timestamp)) }))
    .sort((a, b) => (a.t ?? Infinity) - (b.t ?? Infinity) || a.i - b.i);
  return (
    <div>
      <ol className="azd-vtl">
        {events.map(({ e, i }) => (
          <li key={i} className="azd-vtl-item">
            <div className="azd-vtl-when">
              {asString(e.timestamp) ? formatDateTime(asString(e.timestamp)) : "—"}
              {asString(e.host) && <span className="azd-vtl-host">{asString(e.host)}</span>}
            </div>
            <Markdown text={asString(e.description)} className="azd-vtl-desc" />
            <ExtraKeys obj={e} known={["timestamp", "host", "description"]} title="More" />
          </li>
        ))}
      </ol>
      <ExtraKeys obj={data} known={["events"]} title="Other fields" />
    </div>
  );
}

function IocsView({ data, attachmentId }: { readonly data: Data; readonly attachmentId: string }) {
  const { api } = useDetailContext();
  const categories = iocCategories(data);
  const total = categories.reduce((n, c) => n + c.items.length, 0);
  return (
    <div className="azd-iocs">
      <div className="azd-iocs-bar">
        <span className="azd-muted">
          {total} indicator{total === 1 ? "" : "s"} in {categories.length} categor{categories.length === 1 ? "y" : "ies"}
        </span>
        <button
          type="button"
          className="azd-btn azd-btn--sm"
          disabled={total === 0}
          onClick={() =>
            api.downloadFile({
              filename: `iocs-${attachmentId.slice(0, 40)}.csv`,
              mimeType: "text/csv",
              text: iocsToCsv(categories),
            })
          }
        >
          <DownloadIcon /> Download CSV
        </button>
      </div>
      {categories.map((c) => (
        <div key={c.key} className="azd-ioc-cat">
          <div className="azd-subhead">
            {c.label} <span className="azd-count">{c.items.length}</span>
          </div>
          {c.items.length === 0 ? (
            <div className="azd-muted">None</div>
          ) : (
            <table className="azd-table azd-ioc-table">
              <tbody>
                {c.items.map((item, i) => (
                  <tr key={`${item.value}-${i}`}>
                    <td className="azd-ioc-value">
                      <code className="azd-mono">{item.value}</code>
                    </td>
                    <td className="azd-ioc-comment">{item.comment}</td>
                    <td className="azd-ioc-copy">
                      <CopyButton text={item.value} label={`${c.label} value`} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}
      <ExtraKeys obj={data} known={categories.map((c) => c.key)} title="Other fields" />
    </div>
  );
}

const HYPOTHESIS_TONE: Record<string, "primary" | "warning" | "default"> = {
  confirmed: "primary",
  investigating: "warning",
  dismissed: "default",
};

function HypothesesView({ data }: { readonly data: Data }) {
  const list = asArray(data.hypotheses).filter(isRecord);
  return (
    <div>
      <ol className="azd-hypotheses">
        {list.map((h, i) => {
          const status = asString(h.status) ?? "unknown";
          const confidence = typeof h.confidence === "number" ? Math.round(h.confidence * 100) : undefined;
          return (
            <li key={i} className={`azd-hypothesis is-${status}`}>
              <div className="azd-hypothesis-head">
                <Badge tone={HYPOTHESIS_TONE[status] ?? "default"}>{humanize(status)}</Badge>
                <span className="azd-hypothesis-candidate">{asString(h.candidate)}</span>
              </div>
              {confidence !== undefined && (
                <div className="azd-confidence" title={`confidence ${String(h.confidence)}`}>
                  <span className="azd-confidence-track">
                    <span className="azd-confidence-fill" style={{ width: `${Math.min(100, Math.max(0, confidence))}%` }} />
                  </span>
                  <span>{confidence}% confidence</span>
                </div>
              )}
              {asString(h.reason) && <Markdown text={asString(h.reason)} />}
              <EvidenceItems evidence={h.evidence} />
              <ExtraKeys obj={h} known={["candidate", "confidence", "status", "reason", "evidence"]} title="More" />
            </li>
          );
        })}
      </ol>
      <RecordedLine data={data} />
      <ExtraKeys obj={data} known={["hypotheses", ...RECORD_KEYS]} title="Other fields" />
    </div>
  );
}

const RULE_KNOWN = ["name", "description", "severity", "risk_score", "type", "language", "query", "enabled", "rule_id", "id", "tags", "threat"];

function RuleView({ data }: { readonly data: Data }) {
  const severity = asString(data.severity);
  const query = asString(data.query);
  return (
    <div>
      <Fields>
        <Field label="Name">{asString(data.name) && <strong>{asString(data.name)}</strong>}</Field>
        <Field label="Rule id">{asString(data.rule_id) && <IdValue value={asString(data.rule_id) as string} label="rule id" />}</Field>
        <Field label="Id">{asString(data.id) && <IdValue value={asString(data.id) as string} label="id" />}</Field>
        <Field label="Enabled">{typeof data.enabled === "boolean" && (data.enabled ? "Yes" : "No")}</Field>
        <Field label="Severity">{severity && <Badge tone={severityTone(severity)}>{severity}</Badge>}</Field>
        <Field label="Risk score">{asString(data.risk_score)}</Field>
        <Field label="Type">{[asString(data.type), asString(data.language)].filter(Boolean).join(" · ")}</Field>
        <Field label="Tags">{asStringArray(data.tags).length > 0 && <ChipList values={asStringArray(data.tags)} />}</Field>
        <Field label="MITRE ATT&CK">{asArray(data.threat).length > 0 && <MitreThreatList threats={data.threat} />}</Field>
      </Fields>
      {asString(data.description) && <Markdown text={asString(data.description)} />}
      {query && <CodeBlock code={query} />}
      <ExtraKeys obj={data} known={RULE_KNOWN} title="Other fields" />
    </div>
  );
}

function ThreatView({ data }: { readonly data: Data }) {
  const title = asString(data.title) ?? asString(data.name);
  const severity = asString(data.severity);
  const body = asString(data.summary) ?? asString(data.description);
  return (
    <div>
      {title && <div className="azd-ad-title">{title}</div>}
      <div className="azd-ad-meta">
        {severity && <Badge tone={severityTone(severity)}>{severity}</Badge>}
        {asString(data.source) && <span>{asString(data.source)}</span>}
        {asString(data.report_id) && <IdValue value={asString(data.report_id) as string} label="report id" />}
      </div>
      {body && <Markdown text={body} />}
      <ExtraKeys obj={data} known={["title", "name", "severity", "source", "report_id", "summary", "description"]} title="Other fields" />
    </div>
  );
}

function EsqlView({ data }: { readonly data: Data }) {
  const query = asString(data.query) ?? asString(data.esql);
  return (
    <div>
      {asString(data.description) && <Markdown text={asString(data.description)} />}
      {query && <CodeBlock code={query} label="ES|QL query" />}
      <ExtraKeys obj={data} known={["query", "esql", "description"]} title="Other fields" />
    </div>
  );
}

function TextView({ data }: { readonly data: unknown }) {
  if (typeof data === "string") return <ClampedMarkdown text={data} />;
  const d = isRecord(data) ? data : {};
  return (
    <div>
      <ClampedMarkdown text={asString(d.content) ?? asString(d.text)} />
      <ExtraKeys obj={d} known={["content", "text"]} title="Other fields" />
    </div>
  );
}

function GraphView({ data }: { readonly data: Data }) {
  const nodes = asArray(data.nodes).filter(isRecord);
  const edges = asArray(data.edges).filter(isRecord);
  const label = (n: Data) => asString(isRecord(n.data) ? n.data.label : undefined) ?? asString(n.label) ?? asString(n.id) ?? "?";
  const byId = new Map(nodes.map((n) => [asString(n.id), label(n)]));
  return (
    <div>
      {asString(data.title) && <div className="azd-ad-title">{asString(data.title)}</div>}
      {asString(data.description) && <Markdown text={asString(data.description)} />}
      {edges.length > 0 ? (
        <ul className="azd-graph-edges">
          {edges.map((e, i) => (
            <li key={i}>
              <span className="azd-graph-node">{byId.get(asString(e.source)) ?? asString(e.source)}</span>
              <span className="azd-graph-arrow">→{asString(e.label) ? ` ${asString(e.label)} →` : ""}</span>
              <span className="azd-graph-node">{byId.get(asString(e.target)) ?? asString(e.target)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <ChipList values={nodes.map(label)} />
      )}
      <ExtraKeys obj={data} known={["title", "description", "nodes", "edges"]} title="Other fields" />
      <Collapsible title="Graph data" count={nodes.length}>
        <JsonBlock value={{ nodes, edges }} label="graph JSON" />
      </Collapsible>
    </div>
  );
}

function ProposalAttachmentView({ attachment, data }: { readonly attachment: ConversationAttachment; readonly data: unknown }) {
  const id = proposalIdOfAttachment(attachment);
  const d = isRecord(data) ? data : {};
  if (!id) return <GenericData data={data} />;
  return (
    <div>
      <ProposalRef id={id} title={asString(d.title)} />
      <ExtraKeys obj={d} known={["proposalId", "title"]} title="Other fields" />
    </div>
  );
}

/** Body for one attachment version; unknown types and non-object data fall back to a JSON tree. */
export function AttachmentBody({ attachment, data }: { readonly attachment: ConversationAttachment; readonly data: unknown }) {
  if (attachment.type === PROPOSAL_ATTACHMENT_TYPE) return <ProposalAttachmentView attachment={attachment} data={data} />;
  if (attachment.type === "text") return <TextView data={data} />;
  if (!isRecord(data)) return <GenericData data={data} />;
  switch (attachment.type) {
    case "security.attack_discovery":
      return <AttackDiscoveryView data={data} />;
    case "security.attack_discovery.verdict":
      return <VerdictView data={data} />;
    case "investigation_impact":
      return <ImpactView data={data} />;
    case "security.alerts":
    case "security.alert":
      return <AlertsView data={data} />;
    case "security.investigation.timeline":
      return <TimelineView data={data} />;
    case "security.investigation.iocs":
      return <IocsView data={data} attachmentId={attachment.id} />;
    case "investigation_hypotheses":
      return <HypothesesView data={data} />;
    case "security.rule":
      return <RuleView data={data} />;
    case "security.threat":
    case "security.significant_security_event":
      return <ThreatView data={data} />;
    case "esql":
      return <EsqlView data={data} />;
    case "graph":
      return <GraphView data={data} />;
    default:
      return <GenericData data={data} />;
  }
}

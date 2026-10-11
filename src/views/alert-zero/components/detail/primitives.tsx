/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useMemo, useState } from "react";
import classNames from "classnames";
import { renderSafeMarkdown } from "../../../../shared/safe-markdown";
import { EntityIcon } from "../../../../shared/components/icons/icons";
import type { EnrichedAlert, ProposalWithMetadata } from "../../../../shared/alert-zero-types";
import { lookupAlert, useDetailContext } from "./DetailContext";
import {
  type BadgeTone,
  asArray,
  asString,
  formatDateTime,
  getPhaseMeta,
  initials,
  isRecord,
  safeJson,
  severityColor,
  severityTone,
} from "./helpers";
import { CaretIcon, CheckIcon, CopyIcon, WarningIcon } from "./icons";

// ─── Badges ──────────────────────────────────────────────────────────────

export function Badge({
  tone = "default",
  title,
  children,
}: {
  readonly tone?: BadgeTone;
  readonly title?: string;
  readonly children: React.ReactNode;
}) {
  return (
    <span className={`az-badge az-badge--${tone}`} title={title}>
      {children}
    </span>
  );
}

export function PhaseBadge({ status, decision }: Pick<ProposalWithMetadata, "status" | "decision">) {
  const meta = getPhaseMeta({ status, decision });
  return (
    <Badge tone={meta.tone} title={`status: ${status}${decision ? ` · decision: ${decision}` : ""}`}>
      {meta.label}
    </Badge>
  );
}

// ─── Copy ────────────────────────────────────────────────────────────────

export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Clipboard API is often blocked inside host iframes; fall through.
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

export function CopyButton({
  text,
  label = "value",
  showLabel = false,
  className,
}: {
  readonly text: string;
  readonly label?: string;
  readonly showLabel?: boolean;
  readonly className?: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), 1500);
    return () => clearTimeout(t);
  }, [state]);
  const status = state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : `Copy ${label}`;
  return (
    <button
      type="button"
      className={classNames(showLabel ? "azd-btn azd-btn--sm" : "azd-icon-btn", className, {
        "is-copied": state === "copied",
      })}
      aria-label={`Copy ${label}`}
      title={status}
      onClick={async (e) => {
        e.stopPropagation();
        setState((await copyText(text)) ? "copied" : "failed");
      }}
    >
      {state === "copied" ? <CheckIcon /> : <CopyIcon />}
      {showLabel && <span>{status}</span>}
    </button>
  );
}

export function IdValue({ value, label = "id" }: { readonly value: string; readonly label?: string }) {
  return (
    <span className="azd-id">
      <code className="azd-mono" title={value}>
        {value}
      </code>
      <CopyButton text={value} label={label} />
    </span>
  );
}

// ─── Layout ──────────────────────────────────────────────────────────────

export function Section({
  title,
  count,
  section,
  actions,
  className,
  children,
}: {
  readonly title: React.ReactNode;
  readonly count?: number;
  /** Matches a `FIELD_COVERAGE` label so tests can assert where a field renders. */
  readonly section?: string;
  readonly actions?: React.ReactNode;
  readonly className?: string;
  readonly children: React.ReactNode;
}) {
  return (
    <section className={classNames("azd-section", className)} data-section={section}>
      <header className="azd-section-head">
        <h3 className="azd-section-title">{title}</h3>
        {count !== undefined && <span className="azd-count">{count}</span>}
        {actions && <div className="azd-section-actions">{actions}</div>}
      </header>
      {children}
    </section>
  );
}

export function Fields({ children, className }: { readonly children: React.ReactNode; readonly className?: string }) {
  return <dl className={classNames("azd-fields", className)}>{children}</dl>;
}

export function Field({ label, children }: { readonly label: React.ReactNode; readonly children: React.ReactNode }) {
  if (children === undefined || children === null || children === false || children === "") return null;
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

export function Callout({
  tone,
  title,
  children,
  section,
}: {
  readonly tone: "danger" | "warning" | "primary" | "success" | "default";
  readonly title: React.ReactNode;
  readonly children?: React.ReactNode;
  readonly section?: string;
}) {
  return (
    <div
      className={`azd-callout azd-callout--${tone}`}
      role={tone === "danger" ? "alert" : undefined}
      data-section={section}
    >
      <div className="azd-callout-title">
        {(tone === "danger" || tone === "warning") && <WarningIcon size={13} />}
        <span>{title}</span>
      </div>
      {children && <div className="azd-callout-body">{children}</div>}
    </div>
  );
}

export function Collapsible({
  title,
  count,
  defaultOpen = false,
  actions,
  className,
  children,
}: {
  readonly title: React.ReactNode;
  readonly count?: number;
  readonly defaultOpen?: boolean;
  readonly actions?: React.ReactNode;
  readonly className?: string;
  readonly children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={classNames("azd-collapsible", className, { "is-open": open })}>
      <div className="azd-collapsible-head">
        <button
          type="button"
          className="azd-collapsible-toggle"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          <CaretIcon open={open} />
          <span className="azd-collapsible-title">{title}</span>
          {count !== undefined && <span className="azd-count">{count}</span>}
        </button>
        {actions && <div className="azd-collapsible-actions">{actions}</div>}
      </div>
      {open && <div className="azd-collapsible-body">{children}</div>}
    </div>
  );
}

export function ShowMore<T>({
  items,
  limit,
  render,
  noun = "items",
}: {
  readonly items: readonly T[];
  readonly limit: number;
  readonly render: (item: T, index: number) => React.ReactNode;
  readonly noun?: string;
}) {
  const [all, setAll] = useState(false);
  const visible = all ? items : items.slice(0, limit);
  return (
    <>
      {visible.map(render)}
      {items.length > limit && (
        <button type="button" className="azd-link-btn" onClick={() => setAll((a) => !a)}>
          {all ? "Show fewer" : `Show all ${items.length} ${noun}`}
        </button>
      )}
    </>
  );
}

// ─── Text, markdown, JSON ────────────────────────────────────────────────

export function Markdown({ text, className }: { readonly text: string | undefined; readonly className?: string }) {
  const { api } = useDetailContext();
  const html = useMemo(() => renderSafeMarkdown(text), [text]);
  if (!html) return null;
  return (
    <div
      className={classNames("markdown-body", className)}
      onClick={(e) => {
        const anchor = (e.target as HTMLElement).closest("a");
        if (!anchor) return;
        e.preventDefault();
        const href = anchor.getAttribute("href") ?? "";
        if (/^https?:\/\//i.test(href)) api.openLink(href);
      }}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

export function ClampedMarkdown({
  text,
  threshold = 900,
  className,
}: {
  readonly text: string | undefined;
  readonly threshold?: number;
  readonly className?: string;
}) {
  const [open, setOpen] = useState(false);
  if (!text) return null;
  const long = text.length > threshold;
  return (
    <div className={classNames("azd-clamp", className, { "azd-clamp--closed": long && !open })}>
      <Markdown text={text} />
      {long && (
        <button type="button" className="azd-link-btn" onClick={() => setOpen((o) => !o)}>
          {open ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}

export function JsonBlock({
  value,
  maxChars = 3000,
  label = "JSON",
}: {
  readonly value: unknown;
  readonly maxChars?: number;
  readonly label?: string;
}) {
  const text = useMemo(() => (typeof value === "string" ? value : safeJson(value)), [value]);
  const [all, setAll] = useState(false);
  const long = text.length > maxChars;
  return (
    <div className="azd-json">
      <CopyButton text={text} label={label} className="azd-json-copy" />
      <pre className="az-code az-code--wrap">{long && !all ? `${text.slice(0, maxChars)}…` : text}</pre>
      {long && (
        <button type="button" className="azd-link-btn" onClick={() => setAll((a) => !a)}>
          {all ? "Show less" : `Show all (${text.length.toLocaleString()} chars)`}
        </button>
      )}
    </div>
  );
}

export function CodeBlock({ code, label = "query" }: { readonly code: string; readonly label?: string }) {
  return (
    <div className="azd-json">
      <CopyButton text={code} label={label} className="azd-json-copy" />
      <pre className="az-code az-code--wrap">{code}</pre>
    </div>
  );
}

function LongString({ value }: { readonly value: string }) {
  const [open, setOpen] = useState(false);
  const long = value.length > 280;
  return (
    <span className="azd-kv-longstr">
      <span className="azd-kv-str azd-pre">{long && !open ? `${value.slice(0, 280)}…` : value}</span>
      {long && (
        <button type="button" className="azd-link-btn" onClick={() => setOpen((o) => !o)}>
          {open ? "Less" : `More (${value.length.toLocaleString()} chars)`}
        </button>
      )}
    </span>
  );
}

export function ScalarValue({ value }: { readonly value: unknown }) {
  if (value === null) return <span className="azd-kv-null">null</span>;
  if (value === undefined) return <span className="azd-kv-null">—</span>;
  if (typeof value === "boolean") return <span className="azd-kv-bool">{value ? "true" : "false"}</span>;
  if (typeof value === "number") return <span className="azd-kv-num">{value}</span>;
  if (typeof value === "string") {
    if (value === "") return <span className="azd-kv-null">""</span>;
    return value.length > 120 || value.includes("\n") ? <LongString value={value} /> : <span className="azd-kv-str">{value}</span>;
  }
  return <span className="azd-kv-str">{safeJson(value, 0)}</span>;
}

function isScalar(v: unknown): boolean {
  return v === null || typeof v !== "object";
}

/** Recursive key/value view of any JSON value; nothing is dropped. */
export function ValueTree({
  value,
  depth = 0,
  openDepth = 1,
}: {
  readonly value: unknown;
  readonly depth?: number;
  readonly openDepth?: number;
}) {
  if (isScalar(value)) return <ScalarValue value={value} />;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="azd-kv-null">[ ]</span>;
    if (value.every(isScalar)) {
      return (
        <ul className="azd-kv-list">
          {value.map((v, i) => (
            <li key={i}>
              <ScalarValue value={v} />
            </li>
          ))}
        </ul>
      );
    }
    return <KeyValueTree entries={value.map((v, i) => [`[${i}]`, v])} depth={depth} openDepth={openDepth} />;
  }
  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return <span className="azd-kv-null">{"{ }"}</span>;
    return <KeyValueTree entries={entries} depth={depth} openDepth={openDepth} />;
  }
  return <ScalarValue value={value} />;
}

function summarize(value: unknown): string {
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? "" : "s"}`;
  if (isRecord(value)) {
    const n = Object.keys(value).length;
    return `${n} key${n === 1 ? "" : "s"}`;
  }
  return "";
}

function KeyValueRow({
  name,
  value,
  depth,
  openDepth,
  annotation,
}: {
  readonly name: string;
  readonly value: unknown;
  readonly depth: number;
  readonly openDepth: number;
  readonly annotation?: React.ReactNode;
}) {
  const nested =
    (Array.isArray(value) && value.length > 0 && !value.every(isScalar)) ||
    (isRecord(value) && Object.keys(value).length > 0);
  const [open, setOpen] = useState(depth < openDepth);
  if (!nested) {
    return (
      <div className="azd-kv-row">
        <div className="azd-kv-key">
          <span className="azd-mono">{name}</span>
          {annotation}
        </div>
        <div className="azd-kv-val">
          <ValueTree value={value} depth={depth + 1} openDepth={openDepth} />
        </div>
      </div>
    );
  }
  return (
    <div className="azd-kv-row azd-kv-row--nested">
      <div className="azd-kv-key">
        <button type="button" className="azd-kv-toggle" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          <CaretIcon open={open} />
          <span className="azd-mono">{name}</span>
          <span className="azd-kv-summary">{summarize(value)}</span>
        </button>
        {annotation}
      </div>
      {open && (
        <div className="azd-kv-children">
          <ValueTree value={value} depth={depth + 1} openDepth={openDepth} />
        </div>
      )}
    </div>
  );
}

export function KeyValueTree({
  entries,
  depth = 0,
  openDepth = 1,
  annotate,
}: {
  readonly entries: readonly (readonly [string, unknown])[];
  readonly depth?: number;
  readonly openDepth?: number;
  readonly annotate?: (key: string) => React.ReactNode;
}) {
  return (
    <div className={classNames("azd-kv", { "azd-kv--root": depth === 0 })}>
      {entries.map(([k, v]) => (
        <KeyValueRow key={k} name={k} value={v} depth={depth} openDepth={openDepth} annotation={annotate?.(k)} />
      ))}
    </div>
  );
}

function isEmptyValue(v: unknown): boolean {
  return v === undefined || (Array.isArray(v) && v.length === 0) || (isRecord(v) && Object.keys(v).length === 0);
}

/** Render the keys of `obj` not in `known` so unrecognized inputs are never hidden. */
export function ExtraKeys({
  obj,
  known,
  title = "Other inputs",
}: {
  readonly obj: Record<string, unknown> | undefined;
  readonly known: readonly string[];
  readonly title?: string;
}) {
  if (!obj) return null;
  const extra = Object.entries(obj).filter(([k, v]) => !known.includes(k) && !isEmptyValue(v));
  if (extra.length === 0) return null;
  return (
    <div className="azd-extra">
      <div className="azd-subhead">{title}</div>
      <KeyValueTree entries={extra} openDepth={2} />
    </div>
  );
}

// ─── People, time, entities ──────────────────────────────────────────────

function hueOf(name: string): number {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  return h;
}

export function Avatar({ name, bot = false }: { readonly name: string; readonly bot?: boolean }) {
  const hue = hueOf(name);
  return (
    <span
      className={classNames("azd-avatar", { "azd-avatar--bot": bot })}
      style={bot ? undefined : { background: `hsl(${hue} 30% 26%)`, color: `hsl(${hue} 60% 82%)` }}
      aria-hidden="true"
    >
      {bot ? "AI" : initials(name)}
    </span>
  );
}

export function DateValue({ iso }: { readonly iso: string | undefined }) {
  if (!iso) return null;
  return <time dateTime={iso} title={iso}>{formatDateTime(iso)}</time>;
}

export function EntityChip({
  name,
  id,
  type,
}: {
  readonly name?: string;
  readonly id?: string;
  readonly type?: string;
}) {
  const icon = type === "user" ? EntityIcon.user : type === "host" ? EntityIcon.host : EntityIcon.process;
  return (
    <span className="azd-entity" title={id}>
      <span className="azd-entity-icon">{icon}</span>
      <span className="azd-entity-name">{name ?? id}</span>
      {name && id && name !== id && <code className="azd-entity-id">{id}</code>}
    </span>
  );
}

// ─── Alerts ──────────────────────────────────────────────────────────────

export function AlertRow({ id, alert }: { readonly id: string; readonly alert?: EnrichedAlert }) {
  const style = { "--azd-stripe": severityColor(alert?.severity) } as React.CSSProperties;
  return (
    <div className="azd-alert" style={style} title={alert?.index ? `${alert.index} / ${id}` : id}>
      <div className="azd-alert-main">
        <div className="azd-alert-title">
          {alert?.ruleName ?? <code className="azd-mono">{id}</code>}
        </div>
        {alert && (
          <div className="azd-alert-meta">
            {alert.severity && <Badge tone={severityTone(alert.severity)}>{alert.severity}</Badge>}
            {alert.riskScore !== undefined && <span>risk {alert.riskScore}</span>}
            {alert.host && (
              <span className="azd-inline-entity">
                {EntityIcon.host}
                {alert.host}
              </span>
            )}
            {alert.user && (
              <span className="azd-inline-entity">
                {EntityIcon.user}
                {alert.user}
              </span>
            )}
            {alert.timestamp && <DateValue iso={alert.timestamp} />}
            {alert.workflowStatus && <Badge tone="hollow">{alert.workflowStatus}</Badge>}
          </div>
        )}
        {alert?.reason && <div className="azd-alert-reason">{alert.reason}</div>}
        {alert?.ruleName && <code className="azd-alert-id">{id}</code>}
      </div>
      <CopyButton text={id} label="alert id" />
    </div>
  );
}

export function AlertList({ ids, limit = 6 }: { readonly ids: readonly string[]; readonly limit?: number }) {
  const { alerts } = useDetailContext();
  if (ids.length === 0) return <div className="azd-muted">No alert ids.</div>;
  return (
    <div className="azd-alert-list">
      <ShowMore
        items={ids}
        limit={limit}
        noun="alerts"
        render={(id, i) => <AlertRow key={`${id}-${i}`} id={id} alert={lookupAlert(alerts, id)} />}
      />
    </div>
  );
}

// ─── MITRE ───────────────────────────────────────────────────────────────

/** Defensive MITRE renderer (tactic → technique → subtechnique); LLM-authored input may be partial. */
export function MitreThreatList({ threats }: { readonly threats: unknown }) {
  const list = asArray(threats).filter(isRecord);
  if (list.length === 0) return null;
  return (
    <div className="azd-mitre">
      {list.map((t, i) => {
        const tactic = isRecord(t.tactic) ? t.tactic : {};
        return (
          <div key={i} className="azd-mitre-row">
            <span className="azd-mitre-tactic">
              {[asString(tactic.id), asString(tactic.name)].filter(Boolean).join(" ") || asString(t.framework) || "Tactic"}
            </span>
            {asArray(t.technique)
              .filter(isRecord)
              .map((tech, j) => (
                <React.Fragment key={j}>
                  <span className="azd-mitre-technique">
                    {[asString(tech.id), asString(tech.name)].filter(Boolean).join(" ")}
                  </span>
                  {asArray(tech.subtechnique)
                    .filter(isRecord)
                    .map((sub, k) => (
                      <span key={k} className="azd-mitre-technique azd-mitre-sub">
                        {[asString(sub.id), asString(sub.name)].filter(Boolean).join(" ")}
                      </span>
                    ))}
                </React.Fragment>
              ))}
          </div>
        );
      })}
    </div>
  );
}

export function ChipList({ values, mono = false }: { readonly values: readonly string[]; readonly mono?: boolean }) {
  if (values.length === 0) return null;
  return (
    <div className="azd-chips">
      {values.map((v, i) => (
        <span key={`${v}-${i}`} className={classNames("az-chip", { "azd-chip--sans": !mono })} title={v}>
          {v}
        </span>
      ))}
    </div>
  );
}

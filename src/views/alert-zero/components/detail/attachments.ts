/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AttachmentVersion, ConversationAttachment } from "../../../../shared/alert-zero-types";
import { asArray, asString, csvCell, humanize, isRecord } from "./helpers";

export type EvidenceGroupId =
  | "proposals"
  | "attack"
  | "verdict"
  | "impact"
  | "alerts"
  | "timeline"
  | "iocs"
  | "hypotheses"
  | "rules"
  | "threat"
  | "queries"
  | "notes"
  | "other";

export const EVIDENCE_GROUPS: readonly { readonly id: EvidenceGroupId; readonly label: string }[] = [
  { id: "proposals", label: "Proposals" },
  { id: "attack", label: "Attack" },
  { id: "verdict", label: "Verdict" },
  { id: "impact", label: "Impact" },
  { id: "alerts", label: "Alerts" },
  { id: "timeline", label: "Timeline" },
  { id: "iocs", label: "IOCs" },
  { id: "hypotheses", label: "Hypotheses" },
  { id: "rules", label: "Rules" },
  { id: "threat", label: "Threat & signals" },
  { id: "queries", label: "Queries" },
  { id: "notes", label: "Notes" },
  { id: "other", label: "Other" },
];

export const PROPOSAL_ATTACHMENT_TYPE = "platform.proposal";

const TYPE_INFO: Record<string, { readonly label: string; readonly group: EvidenceGroupId }> = {
  [PROPOSAL_ATTACHMENT_TYPE]: { label: "Proposal", group: "proposals" },
  "security.attack_discovery": { label: "Attack Discovery", group: "attack" },
  "security.attack_discovery.verdict": { label: "Verdict", group: "verdict" },
  investigation_impact: { label: "Impact", group: "impact" },
  "security.alerts": { label: "Alerts", group: "alerts" },
  "security.alert": { label: "Alert", group: "alerts" },
  "security.investigation.timeline": { label: "Timeline", group: "timeline" },
  "security.investigation.iocs": { label: "IOCs", group: "iocs" },
  investigation_hypotheses: { label: "Hypotheses", group: "hypotheses" },
  "security.rule": { label: "Detection rule", group: "rules" },
  "security.threat": { label: "Threat", group: "threat" },
  "security.significant_security_event": { label: "Significant security event", group: "threat" },
  esql: { label: "ES|QL query", group: "queries" },
  text: { label: "Note", group: "notes" },
  investigation_subject: { label: "Investigation subject", group: "other" },
  "security.entity": { label: "Entity", group: "other" },
  screen_context: { label: "Screen context", group: "other" },
  graph: { label: "Graph", group: "other" },
};

export function attachmentTypeLabel(type: string): string {
  return TYPE_INFO[type]?.label ?? humanize(type.replace(/^(security|platform)\./, ""));
}

export function attachmentGroup(type: string): EvidenceGroupId {
  return TYPE_INFO[type]?.group ?? "other";
}

export function getCurrentVersion(a: ConversationAttachment): AttachmentVersion | undefined {
  const versions = a.versions ?? [];
  return versions.find((v) => v.version === a.current_version) ?? versions[versions.length - 1];
}

export function isRemoved(a: ConversationAttachment): boolean {
  return a.active === false;
}

/** Proposal id a `platform.proposal` attachment points at (`data.proposalId`, else `origin`). */
export function proposalIdOfAttachment(a: ConversationAttachment): string | undefined {
  const data = getCurrentVersion(a)?.data;
  return (isRecord(data) ? asString(data.proposalId) : undefined) ?? a.origin;
}

export interface IocItem {
  readonly value: string;
  readonly comment?: string;
}

export interface IocCategory {
  readonly key: string;
  readonly label: string;
  readonly items: readonly IocItem[];
}

const IOC_LABELS: Record<string, string> = {
  shas: "File hashes",
  ips: "IP addresses",
  domains: "Domains",
  urls: "URLs",
  file_paths: "File paths",
  malicious_commands: "Malicious commands",
  compromised_identities: "Compromised identities",
  affected_hosts: "Affected hosts",
};

const IOC_ORDER = Object.keys(IOC_LABELS);

function toIocItem(raw: unknown): IocItem | undefined {
  const scalar = asString(raw);
  if (scalar !== undefined) return { value: scalar };
  if (!isRecord(raw)) return undefined;
  const value = asString(raw.value) ?? JSON.stringify(raw);
  const comment = asString(raw.comment);
  return comment ? { value, comment } : { value };
}

/** Known IOC categories first, then any other array-valued key (future categories). */
export function iocCategories(data: unknown): IocCategory[] {
  if (!isRecord(data)) return [];
  const keys = [
    ...IOC_ORDER.filter((k) => k in data),
    ...Object.keys(data).filter((k) => !IOC_ORDER.includes(k) && Array.isArray(data[k])),
  ];
  return keys.map((key) => ({
    key,
    label: IOC_LABELS[key] ?? humanize(key),
    items: asArray(data[key])
      .map(toIocItem)
      .filter((i): i is IocItem => i !== undefined),
  }));
}

export function iocsToCsv(categories: readonly IocCategory[]): string {
  const rows = [["category", "value", "comment"]];
  for (const c of categories) {
    for (const item of c.items) rows.push([c.key, item.value, item.comment ?? ""]);
  }
  return `${rows.map((r) => r.map(csvCell).join(",")).join("\n")}\n`;
}

/** Attack Discovery `replacements`: anonymized token → original value (object or `[{uuid,value}]`). */
export function toReplacementMap(raw: unknown): Record<string, string> {
  if (isRecord(raw)) {
    return Object.fromEntries(
      Object.entries(raw).filter((e): e is [string, string] => typeof e[1] === "string"),
    );
  }
  const out: Record<string, string> = {};
  for (const item of asArray(raw)) {
    if (!isRecord(item)) continue;
    const key = asString(item.uuid) ?? asString(item.anonymized);
    const value = asString(item.value) ?? asString(item.original);
    if (key && value) out[key] = value;
  }
  return out;
}

export function applyReplacements(text: string, replacements: Record<string, string>): string {
  return Object.entries(replacements).reduce((acc, [token, value]) => acc.split(token).join(value), text);
}

/** Attack Discovery markdown: de-anonymize and turn `{{ field value }}` into inline code. */
export function formatDiscoveryMarkdown(text: string | undefined, replacements: Record<string, string>): string {
  if (!text) return "";
  return applyReplacements(text, replacements)
    .replace(/\{\{\s*[\w.@-]+\s+(.+?)\s*\}\}/g, (_m, value: string) => `\`${value.replace(/`/g, "'")}\``)
    .replace(/\{\{|\}\}/g, "");
}

export function formatDiscoveryTitle(text: string | undefined, replacements: Record<string, string>): string {
  if (!text) return "";
  return applyReplacements(text, replacements)
    .replace(/\{\{\s*[\w.@-]+\s+(.+?)\s*\}\}/g, "$1")
    .replace(/\{\{|\}\}/g, "")
    .trim();
}

export type MessageSegment =
  | { readonly kind: "markdown"; readonly text: string }
  | { readonly kind: "attachment"; readonly id: string };

/** Agent responses embed `<render_attachment id="…" />`; split them out so they render as cards. */
export function splitRenderAttachments(text: string | undefined): MessageSegment[] {
  if (!text) return [];
  const re = /<render_attachment\s+id=["']([^"']+)["'][^>]*?\/?>(?:\s*<\/render_attachment>)?/g;
  const out: MessageSegment[] = [];
  let last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const before = text.slice(last, m.index);
    if (before.trim()) out.push({ kind: "markdown", text: before });
    out.push({ kind: "attachment", id: m[1] });
    last = m.index + m[0].length;
  }
  const rest = text.slice(last);
  if (rest.trim()) out.push({ kind: "markdown", text: rest });
  return out;
}

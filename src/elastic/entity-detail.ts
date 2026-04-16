/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { esRequest } from "./client.js";

export interface EntityDetail {
  type: string;
  value: string;
  fields: { label: string; value: string; mono?: boolean }[];
  events?: { timestamp: string; action: string; detail: string }[];
}

export async function getEntityDetail(type: string, value: string): Promise<EntityDetail> {
  switch (type) {
    case "alert": return getAlertDetail(value);
    case "host": return getHostDetail(value);
    case "user": return getUserDetail(value);
    case "process": return getProcessDetail(value);
    case "ip": return getIPDetail(value);
    default: return { type, value, fields: [] };
  }
}

async function getAlertDetail(ruleName: string): Promise<EntityDetail> {
  const r = await esRequest<{ hits: { hits: { _source: Record<string, unknown> }[] } }>(
    "/.alerts-security.alerts-*/_search",
    { body: { size: 1, sort: [{ "@timestamp": "desc" }], query: { bool: { must: [
      { term: { "kibana.alert.rule.name": ruleName } },
      { term: { "kibana.alert.workflow_status": "open" } },
    ] } } } }
  );
  const src = r.hits.hits[0]?._source;
  if (!src) return { type: "alert", value: ruleName, fields: [{ label: "Status", value: "No matching alert found" }] };

  const threats = src["kibana.alert.rule.threat"] as Array<{ tactic?: { name?: string }; technique?: Array<{ id?: string; name?: string }> }> | undefined;
  const mitre = threats?.flatMap(t => [
    t.tactic?.name,
    ...(t.technique?.map(tech => `${tech.id} ${tech.name}`) || []),
  ].filter(Boolean)).join(", ") || "";

  return {
    type: "alert", value: ruleName,
    fields: [
      { label: "Rule", value: String(src["kibana.alert.rule.name"] || "") },
      { label: "Severity", value: String(src["kibana.alert.severity"] || "") },
      { label: "Risk Score", value: String(src["kibana.alert.risk_score"] || "") },
      { label: "Status", value: String(src["kibana.alert.workflow_status"] || "") },
      { label: "Reason", value: String(src["kibana.alert.reason"] || "") },
      { label: "Host", value: String((src.host as Record<string, unknown>)?.name || "N/A"), mono: true },
      { label: "User", value: String((src.user as Record<string, unknown>)?.name || "N/A"), mono: true },
      { label: "Process", value: String((src.process as Record<string, unknown>)?.name || "N/A"), mono: true },
      { label: "Executable", value: String((src.process as Record<string, unknown>)?.executable || "N/A"), mono: true },
      ...(mitre ? [{ label: "MITRE ATT&CK", value: mitre }] : []),
      { label: "Timestamp", value: String(src["@timestamp"] || ""), mono: true },
      ...(src["kibana.alert.rule.description"] ? [{ label: "Description", value: String(src["kibana.alert.rule.description"]) }] : []),
    ],
  };
}

async function getHostDetail(hostName: string): Promise<EntityDetail> {
  const [procR, netR, alertR] = await Promise.all([
    safeSearch("logs-endpoint.events.process-*", { "host.name": hostName }, 5,
      ["@timestamp", "process.name", "process.executable", "user.name", "process.command_line"]),
    safeSearch("logs-endpoint.events.network-*", { "host.name": hostName }, 5,
      ["@timestamp", "destination.ip", "destination.port", "process.name", "network.protocol"]),
    safeSearch(".alerts-security.alerts-*", { "host.name": hostName }, 3,
      ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity"]),
  ]);

  const fields: EntityDetail["fields"] = [
    { label: "Hostname", value: hostName, mono: true },
  ];

  const firstProc = procR[0];
  if (firstProc) {
    const os = firstProc["host.os.name"] || firstProc["host.os.platform"];
    if (os) fields.push({ label: "OS", value: String(os) });
    const ips = firstProc["host.ip"];
    if (ips) fields.push({ label: "IP", value: String(Array.isArray(ips) ? ips[0] : ips), mono: true });
  }

  fields.push({ label: "Recent Processes", value: procR.map(p => p["process.name"]).filter(Boolean).join(", "), mono: true });
  fields.push({ label: "Recent Connections", value: netR.map(n => `${n["destination.ip"]}:${n["destination.port"]}`).filter(Boolean).join(", "), mono: true });

  if (alertR.length > 0) {
    fields.push({ label: "Open Alerts", value: alertR.map(a => `${a["kibana.alert.severity"]} — ${a["kibana.alert.rule.name"]}`).join("\n") });
  }

  const events = procR.map(p => ({
    timestamp: String(p["@timestamp"] || ""),
    action: "process",
    detail: `${p["user.name"] || "?"} ran ${p["process.name"]}${p["process.command_line"] ? ": " + String(p["process.command_line"]).substring(0, 80) : ""}`,
  }));

  return { type: "host", value: hostName, fields, events };
}

async function getUserDetail(userName: string): Promise<EntityDetail> {
  const [procR, alertR] = await Promise.all([
    safeSearch("logs-endpoint.events.process-*", { "user.name": userName }, 5,
      ["@timestamp", "host.name", "process.name", "process.command_line"]),
    safeSearch(".alerts-security.alerts-*", { "user.name": userName }, 3,
      ["@timestamp", "kibana.alert.rule.name", "kibana.alert.severity", "host.name"]),
  ]);

  const hosts = [...new Set(procR.map(p => p["host.name"]).filter(Boolean))];

  const fields: EntityDetail["fields"] = [
    { label: "Username", value: userName, mono: true },
    { label: "Active Hosts", value: hosts.join(", ") || "None", mono: true },
    { label: "Recent Processes", value: procR.map(p => p["process.name"]).filter(Boolean).join(", "), mono: true },
  ];

  if (alertR.length > 0) {
    fields.push({ label: "Alerts", value: alertR.map(a => `${a["kibana.alert.severity"]} — ${a["kibana.alert.rule.name"]} (${a["host.name"]})`).join("\n") });
  }

  const events = procR.map(p => ({
    timestamp: String(p["@timestamp"] || ""),
    action: "process",
    detail: `${p["process.name"]} on ${p["host.name"]}`,
  }));

  return { type: "user", value: userName, fields, events };
}

async function getProcessDetail(processName: string): Promise<EntityDetail> {
  const procR = await safeSearch("logs-endpoint.events.process-*", { "process.name": processName }, 5,
    ["@timestamp", "host.name", "user.name", "process.executable", "process.command_line", "process.pid", "process.parent.name", "process.parent.executable"]);

  const first = procR[0] || {};
  const fields: EntityDetail["fields"] = [
    { label: "Process", value: processName, mono: true },
    { label: "Executable", value: String(first["process.executable"] || "N/A"), mono: true },
    { label: "Parent", value: String(first["process.parent.name"] || "N/A"), mono: true },
    { label: "Parent Executable", value: String(first["process.parent.executable"] || "N/A"), mono: true },
    { label: "Hosts", value: [...new Set(procR.map(p => p["host.name"]).filter(Boolean))].join(", "), mono: true },
    { label: "Users", value: [...new Set(procR.map(p => p["user.name"]).filter(Boolean))].join(", "), mono: true },
  ];

  if (first["process.command_line"]) {
    fields.push({ label: "Command Line", value: String(first["process.command_line"]), mono: true });
  }

  const events = procR.map(p => ({
    timestamp: String(p["@timestamp"] || ""),
    action: "exec",
    detail: `PID ${p["process.pid"]} on ${p["host.name"]} by ${p["user.name"]}`,
  }));

  return { type: "process", value: processName, fields, events };
}

async function getIPDetail(ip: string): Promise<EntityDetail> {
  const netR = await safeSearch("logs-endpoint.events.network-*", { "destination.ip": ip }, 5,
    ["@timestamp", "host.name", "process.name", "destination.port", "network.protocol", "network.bytes"]);

  const fields: EntityDetail["fields"] = [
    { label: "IP Address", value: ip, mono: true },
    { label: "Hosts Connected", value: [...new Set(netR.map(n => n["host.name"]).filter(Boolean))].join(", "), mono: true },
    { label: "Processes", value: [...new Set(netR.map(n => n["process.name"]).filter(Boolean))].join(", "), mono: true },
    { label: "Ports", value: [...new Set(netR.map(n => n["destination.port"]).filter(Boolean))].join(", "), mono: true },
  ];

  const events = netR.map(n => ({
    timestamp: String(n["@timestamp"] || ""),
    action: "connection",
    detail: `${n["process.name"]} → ${ip}:${n["destination.port"]} (${n["network.protocol"] || "?"})`,
  }));

  return { type: "ip", value: ip, fields, events };
}

async function safeSearch(
  index: string,
  match: Record<string, string>,
  size: number,
  sourceFields: string[],
): Promise<Record<string, unknown>[]> {
  try {
    const must = Object.entries(match).map(([k, v]) => ({ term: { [k]: v } }));
    const r = await esRequest<{ hits: { hits: { _source: Record<string, unknown> }[] } }>(
      `/${index}/_search`,
      { body: { size, sort: [{ "@timestamp": "desc" }], _source: sourceFields, query: { bool: { must } } } }
    );
    return r.hits.hits.map(h => flattenSource(h._source));
  } catch { return []; }
}

function flattenSource(obj: Record<string, unknown>, prefix = ""): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(result, flattenSource(value as Record<string, unknown>, fullKey));
    } else {
      result[fullKey] = value;
    }
  }
  return result;
}

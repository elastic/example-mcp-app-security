/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Fixtures for the Case Management view.
 */

import type { KibanaCase } from "../../src/shared/types";

const NOW = new Date("2026-04-22T14:18:00.000Z");
function hoursAgo(h: number): string { return new Date(NOW.getTime() - h * 3_600_000).toISOString(); }
function daysAgo(d: number): string { return new Date(NOW.getTime() - d * 86_400_000).toISOString(); }

const CASES: KibanaCase[] = [
  {
    id: "case-01",
    version: "WzQyLDFd",
    incremental_id: 61,
    title: "Ransomware staging on win-dc-01",
    description: "Multiple critical alerts suggest credential access followed by lateral movement to the domain controller.",
    status: "open",
    severity: "critical",
    tags: ["malware", "ransomware", "priority-1", "dc", "win"],
    totalAlerts: 14,
    totalComment: 4,
    created_at: hoursAgo(3),
    created_by: { username: "pmanko", full_name: "Pavel Manko" },
    updated_at: hoursAgo(1),
    connector: null,
    settings: {},
  },
  {
    id: "case-02",
    version: "WzQxLDFd",
    incremental_id: 60,
    title: "Suspicious PowerShell bursts — marketing laptops",
    description: "Recurring encoded-command executions across 3 marketing hosts. Looks like a phishing campaign.",
    status: "in-progress",
    severity: "high",
    tags: ["phishing", "powershell", "endpoint"],
    totalAlerts: 9,
    totalComment: 7,
    created_at: hoursAgo(8),
    created_by: { username: "sarah.lee", full_name: "Sarah Lee" },
    updated_at: hoursAgo(2),
    connector: null,
    settings: {},
  },
  {
    id: "case-03",
    version: "WzM5LDFd",
    incremental_id: 58,
    title: "CI runner talking to TOR exit node",
    description: "Outbound TCP:443 to 185.220.101.42 from lin-build-03, confirmed TOR exit.",
    status: "in-progress",
    severity: "high",
    tags: ["network", "ci", "linux"],
    totalAlerts: 3,
    totalComment: 2,
    created_at: daysAgo(1),
    created_by: { username: "karl.admin", full_name: "Karl Admin" },
    updated_at: hoursAgo(6),
    connector: null,
    settings: {},
  },
  {
    id: "case-04",
    version: "WzM4LDFd",
    incremental_id: 57,
    title: "Scheduled task persistence — investigate",
    description: "Unusual 'BackupAgent' scheduled task created on multiple desktops.",
    status: "open",
    severity: "medium",
    tags: ["persistence", "endpoint"],
    totalAlerts: 5,
    totalComment: 1,
    created_at: daysAgo(1),
    created_by: { username: "pmanko", full_name: "Pavel Manko" },
    updated_at: daysAgo(1),
    connector: null,
    settings: {},
  },
  {
    id: "case-05",
    version: "WzM3LDFd",
    incremental_id: 55,
    title: "DNS tunneling suspected — lin-build-03",
    description: "Long TXT-record queries pattern. Might be a misconfigured monitoring agent; needs confirmation.",
    status: "open",
    severity: "low",
    tags: ["network", "dns"],
    totalAlerts: 2,
    totalComment: 0,
    created_at: daysAgo(2),
    created_by: { username: "jane.doe", full_name: "Jane Doe" },
    updated_at: daysAgo(2),
    connector: null,
    settings: {},
  },
  {
    id: "case-06",
    version: "WzMyLDFd",
    incremental_id: 52,
    title: "Credential access via LSASS dump",
    description: "Resolved: tooling confirmed as red-team exercise. Closing.",
    status: "closed",
    severity: "high",
    tags: ["credential-access", "red-team", "resolved"],
    totalAlerts: 6,
    totalComment: 5,
    created_at: daysAgo(4),
    created_by: { username: "karl.admin", full_name: "Karl Admin" },
    updated_at: daysAgo(1),
    connector: null,
    settings: {},
  },
  {
    id: "case-07",
    version: "WzMwLDFd",
    incremental_id: 49,
    title: "Stale — unauthorized SaaS usage",
    description: "User downloaded company data into personal Dropbox. HR handled.",
    status: "closed",
    severity: "medium",
    tags: ["data-loss", "hr", "resolved"],
    totalAlerts: 1,
    totalComment: 3,
    created_at: daysAgo(7),
    created_by: { username: "sarah.lee", full_name: "Sarah Lee" },
    updated_at: daysAgo(5),
    connector: null,
    settings: {},
  },
];

function listCases(args: { status?: string; search?: string }) {
  let out = CASES.slice();
  if (args.status && args.status !== "all") {
    out = out.filter((c) => c.status === args.status);
  }
  if (args.search) {
    const q = args.search.toLowerCase();
    out = out.filter((c) =>
      c.title.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }
  return { cases: out, total: out.length };
}

function getCase(args: { caseId: string }) {
  return CASES.find((c) => c.id === args.caseId) ?? CASES[0];
}

const CASE_ALERTS_BY_ID: Record<string, unknown[]> = {
  "case-01": [
    { _id: "al-1001", _source: { "@timestamp": hoursAgo(3), "kibana.alert.rule.name": "Suspicious PowerShell Encoded Command", "kibana.alert.severity": "critical", "kibana.alert.risk_score": 92 } },
    { _id: "al-1002", _source: { "@timestamp": hoursAgo(2), "kibana.alert.rule.name": "Credential Access via LSASS Memory Dump", "kibana.alert.severity": "critical", "kibana.alert.risk_score": 88 } },
  ],
};

const CASE_COMMENTS_BY_ID: Record<string, { comments: unknown[] }> = {
  "case-01": {
    comments: [
      { id: "c1", type: "user", comment: "Picked this up. Pulling process trees now.", created_at: hoursAgo(3), created_by: { username: "pmanko", full_name: "Pavel Manko" } },
      { id: "c2", type: "user", comment: "Confirmed LSASS dump via ProcDump. Isolating host.", created_at: hoursAgo(2), created_by: { username: "pmanko", full_name: "Pavel Manko" } },
      { id: "c3", type: "user", comment: "Host is off the network. Need memory forensics next.", created_at: hoursAgo(1), created_by: { username: "karl.admin", full_name: "Karl Admin" } },
    ],
  },
};

export default {
  "list-cases": (args: { status?: string; search?: string }) => listCases(args),
  "get-case": (args: { caseId: string }) => getCase(args),
  "get-case-alerts": (args: { caseId: string }) => CASE_ALERTS_BY_ID[args.caseId] ?? [],
  "get-case-comments": (args: { caseId: string }) => CASE_COMMENTS_BY_ID[args.caseId] ?? { comments: [] },
  "create-case": (args: { title?: string }) => ({
    id: `case-${Math.floor(Math.random() * 9000) + 1000}`,
    incremental_id: Math.floor(Math.random() * 90) + 62,
    title: args.title ?? "New case",
    status: "open",
  }),
  "update-case": (_args: { caseId: string; version: string; status?: string }) => ({ updated: true }),
} as Record<string, unknown | ((args: any) => unknown)>;

export const variants: Record<string, Record<string, unknown>> = {
  empty: {
    "list-cases": { cases: [], total: 0 },
  },
};

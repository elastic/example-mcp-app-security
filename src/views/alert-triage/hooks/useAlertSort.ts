/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useMemo } from "react";
import type { AlertSummary, SecurityAlert } from "../../../shared/types";
import { SEVERITY_RANK } from "../../../shared/components";
import type { Severity } from "../../../shared/components";

export type SortKey = "severity" | "risk" | "newest" | "oldest" | "rule" | "host";
export type GroupKey = "none" | "host" | "user" | "process";

export interface AlertGroup {
  key: string;
  name: string;
  subtitle?: string;
  topSeverity: Severity;
  alerts: SecurityAlert[];
}

const SEV_RANK = SEVERITY_RANK;

/** Sort the alerts in a summary using a SortKey. Pure helper — exported for unit tests. */
export function sortAlerts(alerts: SecurityAlert[], sortBy: SortKey): SecurityAlert[] {
  const arr = [...alerts];
  switch (sortBy) {
    case "severity":
      arr.sort((a, b) =>
        (SEV_RANK[b._source["kibana.alert.severity"]?.toLowerCase() || ""] || 0) -
        (SEV_RANK[a._source["kibana.alert.severity"]?.toLowerCase() || ""] || 0));
      break;
    case "risk":
      arr.sort((a, b) => (b._source["kibana.alert.risk_score"] || 0) - (a._source["kibana.alert.risk_score"] || 0));
      break;
    case "newest":
      arr.sort((a, b) => new Date(b._source["@timestamp"]).getTime() - new Date(a._source["@timestamp"]).getTime());
      break;
    case "oldest":
      arr.sort((a, b) => new Date(a._source["@timestamp"]).getTime() - new Date(b._source["@timestamp"]).getTime());
      break;
    case "rule":
      arr.sort((a, b) => (a._source["kibana.alert.rule.name"] || "").localeCompare(b._source["kibana.alert.rule.name"] || ""));
      break;
    case "host":
      arr.sort((a, b) => (a._source.host?.name || "").localeCompare(b._source.host?.name || ""));
      break;
  }
  return arr;
}

/** Bucket the (already-sorted) alerts by host/user/process. Pure helper. */
export function groupAlerts(sortedAlerts: SecurityAlert[], groupBy: GroupKey): AlertGroup[] | null {
  if (groupBy === "none") return null;
  const buckets = new Map<string, AlertGroup>();
  for (const a of sortedAlerts) {
    const src = a._source;
    let key: string | undefined;
    let name: string | undefined;
    let subtitle: string | undefined;
    if (groupBy === "host") {
      name = src.host?.name;
      key = name;
      const os = src.host?.os?.name || src.host?.os?.platform;
      subtitle = os ? `${os} host` : (src.host?.ip?.[0] ? `IP ${src.host.ip[0]}` : undefined);
    } else if (groupBy === "user") {
      name = src.user?.name;
      key = src.user?.domain ? `${src.user.domain}\\${name}` : name;
      subtitle = src.user?.domain ? `Domain ${src.user.domain}` : (src.host?.name ? `Seen on ${src.host.name}` : undefined);
    } else if (groupBy === "process") {
      name = src.process?.name;
      key = name;
      subtitle = src.process?.executable || (src.process?.parent?.name ? `Parent ${src.process.parent.name}` : undefined);
    }
    if (!key || !name) continue;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { key, name, subtitle, topSeverity: "low", alerts: [] };
      buckets.set(key, bucket);
    }
    bucket.alerts.push(a);
    const sev = (src["kibana.alert.severity"]?.toLowerCase() || "low") as Severity;
    if ((SEV_RANK[sev] || 0) > (SEV_RANK[bucket.topSeverity] || 0)) bucket.topSeverity = sev;
  }
  // Sort groups: highest severity first, then by alert count desc, then alphabetically.
  return [...buckets.values()].sort((a, b) => {
    const d = (SEV_RANK[b.topSeverity] || 0) - (SEV_RANK[a.topSeverity] || 0);
    if (d !== 0) return d;
    const c = b.alerts.length - a.alerts.length;
    if (c !== 0) return c;
    return a.name.localeCompare(b.name);
  });
}

/**
 * Memoised view-state for the alert-triage list: the sorted list, plus the
 * grouped buckets when `groupBy !== "none"`. Pulled out of `App.tsx` so the
 * pure sort/group logic is easy to unit-test in isolation.
 */
export function useAlertSort(summary: AlertSummary | null, sortBy: SortKey, groupBy: GroupKey) {
  const sortedAlerts = useMemo(() => {
    if (!summary) return [] as SecurityAlert[];
    return sortAlerts(summary.alerts, sortBy);
  }, [summary, sortBy]);

  const groupedAlerts = useMemo(
    () => groupAlerts(sortedAlerts, groupBy),
    [sortedAlerts, groupBy],
  );

  return { sortedAlerts, groupedAlerts };
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import React from "react";
import { SeverityBadge } from "../../../shared/severity";
import { timeAgo } from "../../../shared/theme";
import type { AlertContext, SecurityAlert } from "../../../shared/types";

interface InvestigationPanelProps {
  context: AlertContext;
  alert: SecurityAlert;
  tab: "network" | "related";
}

export function InvestigationPanel({ context, alert, tab }: InvestigationPanelProps) {
  if (tab === "network") return <NetworkTab events={context.networkEvents} />;
  if (tab === "related") return <RelatedTab alerts={context.relatedAlerts} />;
  return null;
}

function NetworkTab({ events }: { events: AlertContext["networkEvents"] }) {
  if (!events.length) {
    return <div className="empty-state">No network events in the investigation window.</div>;
  }

  return (
    <table className="network-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Protocol</th>
          <th>Process</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {events.map((ev, i) => (
          <tr key={i}>
            <td style={{ color: "var(--text-dim)" }}>
              {new Date(ev["@timestamp"]).toLocaleTimeString(undefined, {
                hour: "2-digit", minute: "2-digit", second: "2-digit",
              })}
            </td>
            <td>{ev.source?.ip || "—"}{ev.source?.port ? `:${ev.source.port}` : ""}</td>
            <td>{ev.destination?.ip || "—"}{ev.destination?.port ? `:${ev.destination.port}` : ""}</td>
            <td>{ev.network?.protocol || ev.dns?.question?.name || "—"}</td>
            <td>{ev.process?.name || "—"}</td>
            <td style={{ color: "var(--text-dim)" }}>{ev.event?.action || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RelatedTab({ alerts }: { alerts: SecurityAlert[] }) {
  if (!alerts.length) {
    return <div className="empty-state">No related alerts in the investigation window.</div>;
  }

  return (
    <div>
      {alerts.map((a) => {
        const src = a._source;
        return (
          <div key={a._id} className="related-alert-row">
            <SeverityBadge severity={src["kibana.alert.severity"]} />
            <span style={{ flex: 1, fontWeight: 600, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {src["kibana.alert.rule.name"]}
            </span>
            {src.host?.name && (
              <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                {src.host.name}
              </span>
            )}
            <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--font-mono)", flexShrink: 0 }}>
              {timeAgo(src["@timestamp"])}
            </span>
          </div>
        );
      })}
    </div>
  );
}

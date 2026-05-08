/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import type { NetworkEvent } from "../../../shared/types";

export interface NetworkTableProps {
  events: NetworkEvent[];
}

/** Table rendered inside the alert-detail "Network" section. */
export function NetworkTable({ events }: NetworkTableProps) {
  if (events.length === 0) {
    return (
      <div className="network-table-box">
        <div className="alert-detail-empty">No network events.</div>
      </div>
    );
  }
  return (
    <div className="network-table-box">
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
          {events.map((e, i) => {
            const ts = e["@timestamp"]
              ? new Date(e["@timestamp"]).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true })
              : "—";
            const src = e.source?.ip ? `${e.source.ip}${e.source.port ? `:${e.source.port}` : ""}` : "—";
            const dst = e.destination?.ip
              ? `${e.destination.ip}${e.destination.port ? `:${e.destination.port}` : ""}`
              : (e.destination?.port ? `—:${e.destination.port}` : "—");
            const proto = e.network?.protocol || "—";
            const proc = e.process?.name || "—";
            const action = e.event?.action || "—";
            return (
              <tr key={i}>
                <td>{ts}</td>
                <td>{src}</td>
                <td>{dst}</td>
                <td>{proto}</td>
                <td>{proc}</td>
                <td>{action}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

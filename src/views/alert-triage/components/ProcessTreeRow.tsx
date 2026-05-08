/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import type { ProcessEvent } from "../../../shared/types";

export interface ProcessTreeRowProps {
  event: ProcessEvent;
}

/** Single row inside the alert-detail "Process tree" section. */
export function ProcessTreeRow({ event }: ProcessTreeRowProps) {
  const name = event.process?.name || "unknown";
  const pid = event.process?.pid;
  const action = event.event?.action || "";
  const exe = event.process?.executable || "";
  const args = event.process?.args?.join(" ") || "";
  const cmd = exe || args;
  const ts = event["@timestamp"]
    ? new Date(event["@timestamp"]).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true })
    : "";
  return (
    <div className="process-tree-row">
      <div className="process-tree-row-main">
        <div className="process-tree-row-title">
          <span className="process-tree-row-name">{name}</span>
          {pid !== undefined && <span> PID {pid}</span>}
          {action && <span> {action}</span>}
        </div>
        {cmd && <div className="process-tree-row-cmd">{cmd}</div>}
      </div>
      {ts && <div className="process-tree-row-time">{ts}</div>}
    </div>
  );
}

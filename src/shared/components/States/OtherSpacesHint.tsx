/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useState } from "react";
import { useMcpApp } from "../../hooks/useMcpApp";
import { useSpaces } from "../../hooks/useSpaces";
import { parseSpaceCountsResult, spaceDisplayName } from "../../space-calls";
import { COUNT_BY_SPACE_TOOL, type SpaceCountKind } from "../../spaces";
import "./OtherSpacesHint.css";

const NOUN: Record<SpaceCountKind, { one: string; other: string }> = {
  alerts: { one: "open alert", other: "open alerts" },
  discoveries: { one: "attack discovery", other: "attack discoveries" },
};

export interface OtherSpacesHintProps {
  kind: SpaceCountKind;
  /** Look-back window of the view, so counts match what the view would show. */
  days?: number;
}

/**
 * Shown inside an empty state when the active Kibana space has nothing to
 * show but other spaces the API key can read do. Each row switches the view
 * to that space for the session.
 */
export function OtherSpacesHint({ kind, days }: OtherSpacesHintProps) {
  const { connected, getApp } = useMcpApp();
  const { active, spaces, setActiveSpace } = useSpaces();
  const [counts, setCounts] = useState<Record<string, number> | null>(null);
  const enabled = connected && spaces.length > 1;

  useEffect(() => {
    if (!enabled) return;
    const app = getApp();
    if (!app) return;
    let cancelled = false;
    app
      .callServerTool({
        name: COUNT_BY_SPACE_TOOL,
        arguments: days === undefined ? { kind } : { kind, days },
      })
      .then((result) => {
        if (!cancelled) setCounts(parseSpaceCountsResult(result)?.counts ?? null);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [enabled, getApp, kind, days]);

  if (!enabled || !counts) return null;

  // Counts can include spaces the key can read indices for but can't open in Kibana.
  const openable = new Set(spaces.map((s) => s.id));
  const others = Object.entries(counts)
    .filter(([id, n]) => id !== active && n > 0 && openable.has(id))
    .sort((a, b) => b[1] - a[1]);
  if (others.length === 0) return null;

  const total = others.reduce((sum, [, n]) => sum + n, 0);
  const noun = total === 1 ? NOUN[kind].one : NOUN[kind].other;

  return (
    <div className="other-spaces-hint">
      <div className="other-spaces-hint-title">
        Nothing here in <strong>{spaceDisplayName(spaces, active)}</strong>, but{" "}
        {total.toLocaleString()} {noun} {total === 1 ? "is in another space" : "are in other spaces"}:
      </div>
      <ul className="other-spaces-hint-list">
        {others.map(([id, n]) => (
          <li key={id}>
            <button
              type="button"
              className="other-spaces-hint-row"
              onClick={() => void setActiveSpace(id)}
            >
              <span className="other-spaces-hint-name">{spaceDisplayName(spaces, id)}</span>
              <span className="other-spaces-hint-count">{n.toLocaleString()}</span>
              <span className="other-spaces-hint-go" aria-hidden="true">View →</span>
            </button>
          </li>
        ))}
      </ul>
      <div className="other-spaces-hint-action">
        Click a space to view it for this session. To change your default, set the{" "}
        <strong>Kibana space</strong> in your Elastic Security connection settings.
      </div>
    </div>
  );
}

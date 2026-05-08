/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from "react";
import { timeAgo } from "../../../shared/theme";
import { renderMarkdown } from "../../../shared/markdown";

export interface CommentRowProps {
  /** Raw comment object as returned by the Kibana Cases API. */
  comment: unknown;
}

/** Single comment row inside the case-detail "Comments" section. */
export function CommentRow({ comment }: CommentRowProps) {
  const c = (comment || {}) as Record<string, unknown>;
  const by = (c.created_by || {}) as Record<string, unknown>;
  const author = String(by.full_name || by.username || "Unknown");
  const email = typeof by.email === "string" ? by.email : "";
  const body = String(c.comment || c.text || c.body || "");
  const bodyHtml = useMemo(() => renderMarkdown(body), [body]);
  const ts = String(c.created_at || c.timestamp || "");
  const initials = author
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() || "")
    .join("") || "?";
  // Deterministic pastel hue from author string
  const hue = (() => {
    let h = 0;
    for (let i = 0; i < author.length; i++) h = (h * 31 + author.charCodeAt(i)) % 360;
    return h;
  })();
  return (
    <div className="case-detail-comment-row">
      <div
        className="case-detail-comment-avatar"
        style={{
          background: `hsl(${hue} 30% 22%)`,
          color: `hsl(${hue} 55% 78%)`,
          borderColor: `hsl(${hue} 30% 32%)`,
        }}
        aria-hidden="true"
      >
        {initials}
      </div>
      <div className="case-detail-comment-main">
        <div className="case-detail-comment-row-head">
          <span className="case-detail-comment-author" title={email || undefined}>{author}</span>
          <span className="case-detail-comment-sep" aria-hidden="true">·</span>
          <span className="case-detail-comment-action">commented</span>
          {ts && (
            <>
              <span className="case-detail-comment-sep" aria-hidden="true">·</span>
              <span className="case-detail-comment-time" title={ts}>{timeAgo(ts)}</span>
            </>
          )}
        </div>
        <div
          className="case-detail-comment-body markdown-body"
          dangerouslySetInnerHTML={{ __html: bodyHtml }}
        />
      </div>
    </div>
  );
}

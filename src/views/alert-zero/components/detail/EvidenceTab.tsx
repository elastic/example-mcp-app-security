/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useMemo, useRef, useState } from "react";
import classNames from "classnames";
import { EmptyState, ErrorBoundary, LoadingState, ToggleSwitch } from "../../../../shared/components";
import type { AlertZeroInvestigation, ConversationAttachment } from "../../../../shared/alert-zero-types";
import { AttachmentBody } from "./attachmentRenderers";
import {
  EVIDENCE_GROUPS,
  attachmentGroup,
  attachmentTypeLabel,
  getCurrentVersion,
  isRemoved,
} from "./attachments";
import { safeJson } from "./helpers";
import { Badge, Callout, Collapsible, CopyButton, DateValue, IdValue, JsonBlock } from "./primitives";

export interface EvidenceFocus {
  readonly id: string;
  readonly nonce: number;
}

export interface EvidenceTabProps {
  readonly investigation?: AlertZeroInvestigation;
  readonly loading: boolean;
  readonly error?: string;
  readonly onRetry: () => void;
  readonly focus?: EvidenceFocus;
}

function AttachmentCard({
  attachment: a,
  highlighted,
}: {
  readonly attachment: ConversationAttachment;
  readonly highlighted: boolean;
}) {
  const versions = a.versions ?? [];
  const current = getCurrentVersion(a);
  const [selected, setSelected] = useState<number | undefined>();
  const shown = (selected !== undefined ? versions.find((v) => v.version === selected) : undefined) ?? current;
  const removed = isRemoved(a);
  return (
    <article
      className={classNames("azd-att", { "is-removed": removed, "is-highlighted": highlighted })}
      data-attachment-id={a.id}
      aria-label={`${attachmentTypeLabel(a.type)} attachment`}
    >
      <header className="azd-att-head">
        <div className="azd-att-title">
          <span className="azd-att-type">{attachmentTypeLabel(a.type)}</span>
          {a.description && <span className="azd-att-desc">{a.description}</span>}
        </div>
        <div className="azd-att-meta">
          <span>
            v{a.current_version} of {versions.length}
          </span>
          {current?.created_at && <DateValue iso={current.created_at} />}
          {a.origin && (
            <span className="azd-att-origin">
              origin <IdValue value={a.origin} label="origin" />
            </span>
          )}
          {removed && <Badge tone="danger">Removed</Badge>}
          {a.hidden && <Badge tone="hollow">Hidden</Badge>}
          {a.readonly && <Badge tone="hollow">Read-only</Badge>}
        </div>
      </header>
      {versions.length > 1 && (
        <div className="azd-att-versions" role="group" aria-label="Versions">
          {versions.map((v) => (
            <button
              key={v.version}
              type="button"
              className={classNames("azd-version-btn", { "is-active": v.version === shown?.version })}
              aria-pressed={v.version === shown?.version}
              onClick={() => setSelected(v.version === a.current_version ? undefined : v.version)}
              title={v.created_at}
            >
              v{v.version}
              {v.version === a.current_version ? " (current)" : ""}
            </button>
          ))}
        </div>
      )}
      <div className="azd-att-body">
        <ErrorBoundary fallback={<JsonBlock value={shown?.data} />}>
          <AttachmentBody attachment={a} data={shown?.data} />
        </ErrorBoundary>
      </div>
      <Collapsible title="Raw JSON" actions={<CopyButton text={safeJson(a)} label="attachment JSON" />}>
        <JsonBlock value={a} label="attachment JSON" />
      </Collapsible>
    </article>
  );
}

export function EvidenceTab({ investigation, loading, error, onRetry, focus }: EvidenceTabProps) {
  const [showRemoved, setShowRemoved] = useState(false);
  const [highlight, setHighlight] = useState<string | undefined>();
  const [scrollTarget, setScrollTarget] = useState<EvidenceFocus | undefined>();
  const rootRef = useRef<HTMLDivElement>(null);
  const attachments = useMemo(() => investigation?.conversation.attachments ?? [], [investigation]);
  const removedCount = attachments.filter(isRemoved).length;
  const attachmentsRef = useRef(attachments);
  attachmentsRef.current = attachments;

  useEffect(() => {
    if (!focus) return;
    const target = attachmentsRef.current.find((a) => a.id === focus.id);
    if (target && isRemoved(target)) setShowRemoved(true);
    setHighlight(focus.id);
    setScrollTarget(focus);
    const t = setTimeout(() => setHighlight(undefined), 2600);
    return () => clearTimeout(t);
  }, [focus]);

  useEffect(() => {
    if (!scrollTarget) return;
    const el = Array.from(rootRef.current?.querySelectorAll<HTMLElement>("[data-attachment-id]") ?? []).find(
      (node) => node.dataset.attachmentId === scrollTarget.id,
    );
    el?.scrollIntoView?.({ behavior: "smooth", block: "start" });
    setScrollTarget(undefined);
  }, [scrollTarget, showRemoved]);

  const groups = useMemo(() => {
    const visible = attachments.filter((a) => showRemoved || !isRemoved(a));
    return EVIDENCE_GROUPS.map((g) => ({ ...g, items: visible.filter((a) => attachmentGroup(a.type) === g.id) })).filter(
      (g) => g.items.length > 0,
    );
  }, [attachments, showRemoved]);

  if (!investigation) {
    if (loading) return <LoadingState>Loading evidence…</LoadingState>;
    return (
      <Callout tone="danger" title="Couldn't load the investigation">
        <div>{error ?? "Unknown error"}</div>
        <button type="button" className="azd-btn azd-btn--sm" onClick={onRetry}>
          Retry
        </button>
      </Callout>
    );
  }

  const activeCount = attachments.length - removedCount;
  return (
    <div className="azd-tab-body" ref={rootRef}>
      <div className="azd-evidence-bar">
        <span className="azd-muted">
          {activeCount} attachment{activeCount === 1 ? "" : "s"}
          {removedCount > 0 && ` · ${removedCount} removed`}
        </span>
        {removedCount > 0 && (
          <ToggleSwitch label={`Show removed (${removedCount})`} checked={showRemoved} onChange={setShowRemoved} />
        )}
      </div>
      {groups.length > 1 && (
        <nav className="azd-group-nav" aria-label="Evidence groups">
          {groups.map((g) => (
            <button
              key={g.id}
              type="button"
              className="azd-group-chip"
              onClick={() => rootRef.current?.querySelector<HTMLElement>(`[data-group="${g.id}"]`)?.scrollIntoView?.({ behavior: "smooth", block: "start" })}
            >
              {g.label} <span className="azd-count">{g.items.length}</span>
            </button>
          ))}
        </nav>
      )}
      {groups.length === 0 ? (
        <EmptyState>
          {attachments.length === 0 ? "No attachments on this investigation yet." : "All attachments were removed — turn on “Show removed” to see them."}
        </EmptyState>
      ) : (
        groups.map((g) => (
          <section key={g.id} className="azd-group" data-group={g.id}>
            <header className="azd-section-head">
              <h3 className="azd-section-title">{g.label}</h3>
              <span className="azd-count">{g.items.length}</span>
            </header>
            <div className="azd-group-items">
              {g.items.map((a) => (
                <AttachmentCard key={a.id} attachment={a} highlighted={highlight === a.id} />
              ))}
            </div>
          </section>
        ))
      )}
    </div>
  );
}

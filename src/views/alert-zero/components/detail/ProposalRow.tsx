/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import type { ProposalUser, ProposalWithMetadata } from "../../../../shared/alert-zero-types";
import { useDetailContext } from "./DetailContext";
import { formatDateTime, sentenceCase } from "./helpers";
import { Badge, IdValue, PhaseBadge } from "./primitives";

export function UserValue({ user }: { readonly user: ProposalUser }) {
  const name = user.fullName || user.username || user.email || user.profileUid || "Unknown";
  const extras = [
    user.fullName && user.username ? `@${user.username}` : undefined,
    user.email && user.email !== name ? user.email : undefined,
  ].filter(Boolean);
  return (
    <span className="azd-user" title={user.profileUid ? `profile ${user.profileUid}` : undefined}>
      <strong>{name}</strong>
      {extras.length > 0 && <span className="azd-muted"> {extras.join(" · ")}</span>}
    </span>
  );
}

export function ProposalRow({
  proposal,
  label,
}: {
  readonly proposal: ProposalWithMetadata;
  readonly label?: string;
}) {
  const { currentProposalId, selectProposal } = useDetailContext();
  const current = proposal.id === currentProposalId;
  const clickable = !current && Boolean(selectProposal);
  const meta = [
    proposal.action?.name && proposal.action.name !== proposal.title ? proposal.action.name : undefined,
    proposal.impact ? `${sentenceCase(proposal.impact)} impact` : undefined,
    proposal.createdAt ? formatDateTime(proposal.createdAt) : undefined,
  ].filter(Boolean);
  const body = (
    <>
      <span className="azd-prow-main">
        <span className="azd-prow-title">
          {label && <span className="azd-prow-label">{label}</span>}
          {proposal.title}
        </span>
        <span className="azd-prow-meta">
          {meta.join(" · ")}
          <code className="azd-prow-id">{proposal.id}</code>
        </span>
      </span>
      <span className="azd-prow-badges">
        {current && <Badge tone="primary">Viewing</Badge>}
        <PhaseBadge status={proposal.status} decision={proposal.decision} />
      </span>
    </>
  );
  if (clickable) {
    return (
      <button
        type="button"
        className="azd-prow is-clickable"
        onClick={() => selectProposal?.(proposal.id)}
        title="Open this proposal"
      >
        {body}
      </button>
    );
  }
  return <div className={classNames("azd-prow", { "is-current": current })}>{body}</div>;
}

/** Proposal referenced by id (lineage links, `platform.proposal` attachments). */
export function ProposalRef({ id, title }: { readonly id: string; readonly title?: string }) {
  const { proposalsById } = useDetailContext();
  const proposal = proposalsById.get(id);
  if (proposal) return <ProposalRow proposal={proposal} />;
  return (
    <div className="azd-prow is-unknown">
      <span className="azd-prow-main">
        <span className="azd-prow-title">{title ?? "Proposal"}</span>
        <span className="azd-prow-meta">
          <IdValue value={id} label="proposal id" />
          <span className="azd-muted">Not in this proposal&apos;s lineage or siblings</span>
        </span>
      </span>
    </div>
  );
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import classNames from "classnames";
import {
  DetailTabs,
  ErrorBoundary,
  LoadingState,
  RefreshIcon,
  type DetailTab,
} from "../../../../shared/components";
import {
  agentBuilderLink,
  alertZeroLink,
  isAwaitingDecision,
  toProposalCard,
  type AlertZeroInvestigation,
  type AlertZeroLinks,
  type AlertZeroProposalDetail,
  type ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";
import { ALERT_ZERO_APP_TOOLS } from "../../api";
import type { ProposalDetailProps } from "../../types";
import { AgentActivityTab } from "./AgentActivityTab";
import { AllFieldsTab } from "./AllFieldsTab";
import { isRemoved } from "./attachments";
import { DetailContext, type DetailContextValue } from "./DetailContext";
import { EvidenceTab, type EvidenceFocus } from "./EvidenceTab";
import { deadlineLabel, formatDateTime, sentenceCase } from "./helpers";
import { ExternalIcon, SparkleIcon } from "./icons";
import { Badge, Callout, PhaseBadge } from "./primitives";
import { ProposalTab } from "./ProposalTab";
import { buildTimeline } from "./timeline";
import "./detail.css";

type TabId = "proposal" | "activity" | "evidence" | "all";

interface LoadState {
  readonly forId: string;
  readonly detail?: AlertZeroProposalDetail;
  readonly detailError?: string;
  readonly detailLoading: boolean;
  readonly investigation?: AlertZeroInvestigation;
  readonly investigationError?: string;
  readonly investigationLoading: boolean;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function initialState(forId: string): LoadState {
  return { forId, detailLoading: true, investigationLoading: true };
}

function ErrorWithRetry({ title, error, onRetry }: { readonly title: string; readonly error: string; readonly onRetry: () => void }) {
  return (
    <Callout tone="danger" title={title}>
      <div>{error}</div>
      <button type="button" className="azd-btn azd-btn--sm" onClick={onRetry}>
        Retry
      </button>
    </Callout>
  );
}

export function ProposalDetail({
  card,
  spaceId,
  kibanaUrl,
  api,
  reloadToken,
  onSelectProposal,
  renderFooterActions,
}: ProposalDetailProps) {
  const [rawState, setState] = useState<LoadState>(() => initialState(card.id));
  const [localToken, setLocalToken] = useState(0);
  const [tab, setTab] = useState<TabId>("proposal");
  const [focus, setFocus] = useState<EvidenceFocus | undefined>();
  const focusNonce = useRef(0);

  const reload = useCallback(() => setLocalToken((t) => t + 1), []);

  useEffect(() => {
    setTab("proposal");
    setFocus(undefined);
  }, [card.id]);

  useEffect(() => {
    let cancelled = false;
    setState((prev) =>
      prev.forId === card.id
        ? { ...prev, detailLoading: true, investigationLoading: true, detailError: undefined, investigationError: undefined }
        : initialState(card.id),
    );
    api.callTool<AlertZeroProposalDetail>(ALERT_ZERO_APP_TOOLS.detail, { proposalId: card.id, spaceId }).then(
      (detail) => {
        if (!cancelled) setState((s) => ({ ...s, detail, detailLoading: false }));
      },
      (err: unknown) => {
        if (!cancelled) setState((s) => ({ ...s, detailError: errorMessage(err), detailLoading: false }));
      },
    );
    api
      .callTool<AlertZeroInvestigation>(ALERT_ZERO_APP_TOOLS.investigation, { conversationId: card.conversationId, spaceId })
      .then(
        (investigation) => {
          if (!cancelled) setState((s) => ({ ...s, investigation, investigationLoading: false }));
        },
        (err: unknown) => {
          if (!cancelled) setState((s) => ({ ...s, investigationError: errorMessage(err), investigationLoading: false }));
        },
      );
    return () => {
      cancelled = true;
    };
  }, [api, card.id, card.conversationId, spaceId, reloadToken, localToken]);

  const state = rawState.forId === card.id ? rawState : initialState(card.id);
  const { detail, investigation } = state;
  const p = detail?.proposal;

  const timeline = useMemo(() => (investigation ? buildTimeline(investigation.conversation) : []), [investigation]);
  const activeAttachments = useMemo(
    () => (investigation?.conversation.attachments ?? []).filter((a) => !isRemoved(a)).length,
    [investigation],
  );

  const proposalsById = useMemo(() => {
    const map = new Map<string, ProposalWithMetadata>();
    if (detail) {
      for (const r of [...detail.revisionChain, ...detail.siblings]) map.set(r.id, r);
      map.set(detail.proposal.id, detail.proposal);
    }
    return map;
  }, [detail]);

  const attachmentsById = useMemo(
    () => new Map((investigation?.conversation.attachments ?? []).map((a) => [a.id, a])),
    [investigation],
  );

  const assignees = investigation?.assignees ?? card.assignees;

  const selectProposal = useMemo(() => {
    if (!onSelectProposal || !detail) return undefined;
    return (id: string) => {
      const target = proposalsById.get(id);
      if (!target || id === card.id) return;
      const current = detail.proposal;
      const sameInvestigation = target.conversationId === current.conversationId;
      onSelectProposal(
        toProposalCard(
          sameInvestigation
            ? {
                ...target,
                conversationTitle: current.conversationTitle,
                conversationAgentId: current.conversationAgentId,
                conversationAssignees: current.conversationAssignees ?? [],
              }
            : target,
          sameInvestigation ? { assignees } : {},
        ),
      );
    };
  }, [onSelectProposal, detail, proposalsById, card.id, assignees]);

  const jumpToAttachment = useCallback((id: string) => {
    focusNonce.current += 1;
    setTab("evidence");
    setFocus({ id, nonce: focusNonce.current });
  }, []);

  const contextValue = useMemo<DetailContextValue>(
    () => ({
      api,
      currentProposalId: card.id,
      proposalsById,
      attachmentsById,
      alerts: investigation?.alerts ?? {},
      selectProposal,
      jumpToAttachment,
    }),
    [api, card.id, proposalsById, attachmentsById, investigation, selectProposal, jumpToAttachment],
  );

  const status = p?.status ?? card.status;
  const decision = p?.decision;
  const title = p?.title ?? card.title;
  const category = p?.category ?? p?.action?.category ?? card.category;
  const reversible = p?.action?.reversible ?? card.reversible;
  const impact = p?.impact ?? card.impact;
  const confidence = p?.confidence ?? card.confidence;
  const expiresAt = p?.expiresAt ?? card.expiresAt;
  const investigationTitle = p?.conversationTitle ?? card.investigationTitle ?? investigation?.conversation.title;
  const awaiting = isAwaitingDecision({ status, decision });
  const deadline = expiresAt ? (awaiting ? deadlineLabel(expiresAt) : `Deadline ${formatDateTime(expiresAt)}`) : undefined;
  const revision = p?.revision ?? card.revision;
  const chainLength = detail?.revisionChain.length ?? 0;

  const caption = [
    category ? sentenceCase(category) : undefined,
    reversible === undefined ? undefined : reversible ? "Reversible" : "Irreversible",
    impact ? `${sentenceCase(impact)} impact` : undefined,
    confidence ? `${sentenceCase(confidence)} confidence` : undefined,
  ].filter((part): part is string => Boolean(part));

  const links: AlertZeroLinks = detail?.links ??
    investigation?.links ?? {
      alertZero: alertZeroLink(kibanaUrl, spaceId, card.conversationId),
      agentBuilder: agentBuilderLink(kibanaUrl, spaceId, card.conversationId, card.agentId),
    };

  const loading = state.detailLoading || state.investigationLoading;

  const tabs: DetailTab<TabId>[] = [
    { value: "proposal", label: "Proposal" },
    { value: "activity", label: "Agent activity", count: investigation ? timeline.length : undefined },
    { value: "evidence", label: "Evidence", count: investigation ? activeAttachments : undefined },
    { value: "all", label: "All fields" },
  ];

  const investigationProps = {
    investigation,
    loading: state.investigationLoading,
    error: state.investigationError,
    onRetry: reload,
  };

  return (
    <DetailContext.Provider value={contextValue}>
      <div className="azd-root">
        <header className="azd-header" data-section="Header">
          <div className="azd-header-badges">
            <PhaseBadge status={status} decision={decision} />
            {revision !== undefined && chainLength > 1 && (
              <Badge tone="hollow">
                Rev {revision} of {chainLength}
              </Badge>
            )}
            <button
              type="button"
              className={classNames("azd-icon-btn azd-refresh", { "is-spinning": loading })}
              onClick={reload}
              aria-label="Reload proposal"
              title="Reload"
            >
              <RefreshIcon />
            </button>
          </div>
          <h2 className="azd-title">{title}</h2>
          {(caption.length > 0 || deadline) && (
            <div className="azd-caption">
              {caption.map((part) => (
                <span key={part} className="azd-caption-part">
                  {part}
                </span>
              ))}
              {deadline && (
                <span
                  className={classNames("azd-caption-part", { "is-overdue": deadline === "Past deadline" })}
                  title={expiresAt ? `Expires ${formatDateTime(expiresAt)}` : undefined}
                >
                  {deadline}
                </span>
              )}
            </div>
          )}
          {investigationTitle && (
            <div className="azd-header-inv">
              <span className="azd-muted">Investigation</span> <span className="azd-header-inv-title">{investigationTitle}</span>
            </div>
          )}
        </header>

        <div className="azd-tabs">
          <DetailTabs tabs={tabs} value={tab} onChange={setTab} ariaLabel="Proposal detail sections" />
        </div>

        <div className="azd-body" role="tabpanel">
          <ErrorBoundary>
            {tab === "proposal" &&
              (detail ? (
                <>
                  {state.detailError && (
                    <Callout tone="warning" title="Couldn't refresh — showing the last loaded proposal">
                      {state.detailError}
                    </Callout>
                  )}
                  <ProposalTab
                    detail={detail}
                    investigation={investigation}
                    assignees={assignees}
                    onShowAllFields={() => setTab("all")}
                  />
                </>
              ) : state.detailError ? (
                <ErrorWithRetry title="Couldn't load this proposal" error={state.detailError} onRetry={reload} />
              ) : (
                <LoadingState>Loading proposal…</LoadingState>
              ))}
            {tab === "activity" && <AgentActivityTab {...investigationProps} timeline={timeline} />}
            {tab === "evidence" && <EvidenceTab {...investigationProps} focus={focus} />}
            {tab === "all" &&
              (detail ? (
                <AllFieldsTab detail={detail} investigation={investigation} investigationError={state.investigationError} />
              ) : state.detailError ? (
                <ErrorWithRetry title="Couldn't load this proposal" error={state.detailError} onRetry={reload} />
              ) : (
                <LoadingState>Loading proposal…</LoadingState>
              ))}
          </ErrorBoundary>
        </div>

        <footer className="azd-footer">
          {detail && renderFooterActions && (
            <div className="azd-footer-actions">{renderFooterActions({ detail, investigation }, reload)}</div>
          )}
          <div className="azd-footer-links">
            <button type="button" className="azd-btn azd-btn--sm" onClick={() => api.openLink(links.alertZero)}>
              <ExternalIcon /> Open in Alert Zero
            </button>
            <button type="button" className="azd-btn azd-btn--sm" onClick={() => api.openLink(links.agentBuilder)}>
              <ExternalIcon /> Open chat in Agent Builder
            </button>
            <button
              type="button"
              className="azd-btn azd-btn--sm azd-btn--accent"
              onClick={() =>
                api.sendMessage(
                  `Explain Alert Zero proposal ${card.id} ("${title}") using get-alert-zero-proposal, and tell me whether I should approve it.`,
                )
              }
            >
              <SparkleIcon /> Ask Claude about this
            </button>
          </div>
        </footer>
      </div>
    </DetailContext.Provider>
  );
}

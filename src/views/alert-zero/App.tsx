/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import classNames from "classnames";
import {
  spacePrefix,
  type AlertZeroCategoryFilter,
  type AlertZeroListResult,
  type AlertZeroProposalCard,
  type ProposalScope,
} from "../../shared/alert-zero-types";
import { extractToolText } from "../../shared/extract-tool-text";
import { inspectMcpAppBootstrapResult } from "../../shared/mcp-app-bootstrap";
import {
  AppHeader,
  AppShell,
  DetailPane,
  EmptyState,
  LoadingState,
  RefreshIcon,
  ToastProvider,
  TwoPaneLayout,
  useToast,
} from "../../shared/components";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp, useMcpAppBootstrap, useMcpAppEvents } from "../../shared/hooks/useMcpApp";
import { McpAppProvider } from "../../shared/hooks/McpAppProvider";
import { useAnalytics } from "../../shared/hooks/useAnalytics";
import { ALERT_ZERO_APP_TOOLS, useAlertZeroApi } from "./api";
import { ProposalDetail } from "./components/detail/ProposalDetail";
import { DecisionBar } from "./components/decide/DecisionBar";
import { AlertZeroKpis } from "./components/list/AlertZeroKpis";
import { FilterBar } from "./components/list/FilterBar";
import { ProposalList } from "./components/list/ProposalList";
import { StatePanel } from "./components/list/StatePanel";
import { UnavailablePanel } from "./components/list/UnavailablePanel";
import type { GroupBy } from "./components/list/list-model";
import "./styles.css";

interface ListParams {
  readonly scope: ProposalScope;
  readonly category: AlertZeroCategoryFilter;
}

interface Selection {
  readonly card: AlertZeroProposalCard;
  /** False for siblings/revisions opened from the detail pane that aren't list rows. */
  readonly fromList: boolean;
}

const EMPTY_CARDS: readonly AlertZeroProposalCard[] = [];

function isListResult(value: unknown): value is AlertZeroListResult {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<AlertZeroListResult>;
  return !!v.status && typeof v.status === "object" && Array.isArray(v.proposals);
}

function awaitingLine(count: number): string {
  if (count === 0) return "You're all caught up";
  return `${count} ${count === 1 ? "action needs" : "actions need"} you`;
}

export function App() {
  return (
    <ToastProvider>
      <McpAppProvider name="alert-zero" version="1.0.0">
        <AppContent />
      </McpAppProvider>
    </ToastProvider>
  );
}

const BOOTSTRAP_GRACE_MS = 4000;

export function AppContent({ bootstrapGraceMs = BOOTSTRAP_GRACE_MS }: { readonly bootstrapGraceMs?: number } = {}) {
  const { connected, getApp } = useMcpApp();
  const bootstrap = useMcpAppBootstrap("alert-zero");
  const api = useAlertZeroApi(getApp);
  const toast = useToast();
  const fullscreen = useFullscreen(getApp);

  const [result, setResult] = useState<AlertZeroListResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [scope, setScope] = useState<ProposalScope>("all");
  const [category, setCategory] = useState<AlertZeroCategoryFilter>("all");
  const [groupBy, setGroupBy] = useState<GroupBy>("category");
  const [selection, setSelection] = useState<Selection | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  const resultRef = useRef<AlertZeroListResult | null>(null);
  // Bumped on every load and on every pushed result; responses from older
  // requests are dropped so a slow filter change can't overwrite a newer one.
  const requestSeq = useRef(0);

  const applyResult = useCallback((next: AlertZeroListResult) => {
    resultRef.current = next;
    setResult(next);
    setScope(next.scope);
    setCategory(next.category);
    setLoadError(null);
    // A selection that drops out of the list (e.g. just decided) stays open so
    // the detail pane can show the outcome; the user closes it explicitly.
    setSelection((prev) => {
      if (!prev) return prev;
      const match = (next.proposals ?? EMPTY_CARDS).find((p) => p.id === prev.card.id);
      return match ? { card: match, fromList: true } : { ...prev, fromList: false };
    });
  }, []);

  const loadList = useCallback(
    async (params: ListParams): Promise<void> => {
      const seq = ++requestSeq.current;
      setLoading(true);
      try {
        const next = await api.callTool<AlertZeroListResult>(ALERT_ZERO_APP_TOOLS.list, {
          scope: params.scope,
          category: params.category,
          spaceId: resultRef.current?.spaceId,
        });
        if (seq !== requestSeq.current) return;
        applyResult(next);
      } catch (e) {
        if (seq !== requestSeq.current) return;
        const message = e instanceof Error ? e.message : String(e);
        console.error("Failed to load Alert Zero proposals:", e);
        setLoadError(message);
        const current = resultRef.current;
        if (current) {
          setScope(current.scope);
          setCategory(current.category);
        }
        toast.show({ message: `Couldn't load Alert Zero proposals: ${message}`, tone: "danger" });
      } finally {
        if (seq === requestSeq.current) setLoading(false);
      }
    },
    [api, applyResult, toast],
  );

  useMcpAppEvents({
    onToolResult: (pushed) => {
      if (inspectMcpAppBootstrapResult(pushed).status !== "not_bootstrap") return;
      const text = extractToolText(pushed);
      if (!text) return;
      try {
        const data: unknown = JSON.parse(text);
        if (!isListResult(data)) return;
        requestSeq.current += 1;
        applyResult(data);
        setLoading(false);
      } catch {
        /* not a list result */
      }
    },
  });

  useEffect(() => {
    if (bootstrap.status === "idle") return;
    if (bootstrap.status === "error") {
      setLoading(false);
      return;
    }
    requestSeq.current += 1;
    applyResult(bootstrap.payload);
    setLoading(false);
  }, [bootstrap, applyResult]);

  const { trackEvent } = useAnalytics();
  useEffect(() => {
    trackEvent({ eventType: "view_rendered", viewId: "alert-zero" });
  }, [trackEvent]);

  // Hosts often mount the view before the tool result arrives; give the
  // bootstrap a head start so a default-scope self-load doesn't flash first.
  useEffect(() => {
    if (!connected || bootstrap.status !== "idle") return;
    const timer = setTimeout(() => void loadList({ scope: "all", category: "all" }), bootstrapGraceMs);
    return () => clearTimeout(timer);
  }, [connected, bootstrap.status, loadList, bootstrapGraceMs]);

  /** Reload the list and bump `reloadToken` so the open detail pane refetches too. */
  const refresh = useCallback((): Promise<void> => {
    setReloadToken((t) => t + 1);
    return loadList({ scope, category });
  }, [loadList, scope, category]);

  const changeScope = useCallback(
    (next: ProposalScope) => {
      if (next === scope) return;
      setScope(next);
      void loadList({ scope: next, category });
    },
    [loadList, scope, category],
  );

  const changeCategory = useCallback(
    (next: AlertZeroCategoryFilter) => {
      if (next === category) return;
      setCategory(next);
      void loadList({ scope, category: next });
    },
    [loadList, scope, category],
  );

  const clearFilters = useCallback(() => {
    setScope("all");
    setCategory("all");
    void loadList({ scope: "all", category: "all" });
  }, [loadList]);

  const selectFromList = useCallback((card: AlertZeroProposalCard) => {
    setSelection({ card, fromList: true });
  }, []);

  const selectFromDetail = useCallback((card: AlertZeroProposalCard) => {
    const row = resultRef.current?.proposals?.find((p) => p.id === card.id);
    setSelection(row ? { card: row, fromList: true } : { card, fromList: false });
  }, []);

  const cards = useMemo(() => result?.proposals ?? EMPTY_CARDS, [result]);

  if (!connected) {
    return <LoadingState>Connecting…</LoadingState>;
  }

  const available = result?.status.available === true;
  const filtered = scope !== "all" || category !== "all";
  const detailSelection = available ? selection : null;
  const hasDetail = !!detailSelection;
  const showSpace = !!result?.spaceId && result.spaceId !== "default";

  let body: React.ReactNode;
  if (!result) {
    if (loading) {
      body = <LoadingState>Loading Alert Zero proposals…</LoadingState>;
    } else {
      const reason = loadError ?? (bootstrap.status === "error" ? bootstrap.reason : "No data was returned.");
      body = (
        <StatePanel
          title="Couldn't load Alert Zero proposals"
          actions={
            <button type="button" className="az-list-btn" onClick={() => void refresh()}>
              Try again
            </button>
          }
        >
          <p className="az-state-text">{reason}</p>
        </StatePanel>
      );
    }
  } else if (!result.status.available) {
    body = (
      <UnavailablePanel
        status={result.status}
        spaceId={result.spaceId}
        kibanaUrl={result.kibanaUrl}
        checking={loading}
        onCheckAgain={() => void refresh()}
        onOpenLink={api.openLink}
      />
    );
  } else {
    body = (
      <div className="az-list" aria-busy={loading}>
        {loading && <div className="az-progress" aria-hidden="true" />}
        {!hasDetail && (
          <AlertZeroKpis
            totalAwaitingDecision={result.totalAwaitingDecision}
            cards={cards}
            partial={filtered || result.truncated}
          />
        )}
        <FilterBar
          scope={scope}
          category={category}
          groupBy={groupBy}
          countsByCategory={result.countsByCategory}
          totalAwaitingDecision={result.totalAwaitingDecision}
          onScopeChange={changeScope}
          onCategoryChange={changeCategory}
          onGroupByChange={setGroupBy}
        />
        {result.notice && (
          <div className="az-notice" role="note">
            {result.notice}
          </div>
        )}
        {result.truncated && (
          <div className="az-notice" role="note">
            Showing the first {cards.length} proposals.{" "}
            <button
              type="button"
              className="az-link-btn"
              onClick={() => api.openLink(`${result.kibanaUrl}${spacePrefix(result.spaceId)}/app/alertzero`)}
            >
              Open Alert Zero
            </button>{" "}
            to see the rest.
          </div>
        )}
        {cards.length === 0 ? (
          filtered ? (
            <EmptyState>
              <div>No proposals match this filter</div>
              <button type="button" className="az-list-btn az-empty-action" onClick={clearFilters}>
                Show all proposals
              </button>
            </EmptyState>
          ) : (
            <EmptyState>Nothing awaiting your decision</EmptyState>
          )
        ) : (
          <ProposalList
            cards={cards}
            groupBy={groupBy}
            selectedId={selection?.card.id}
            onSelect={selectFromList}
          />
        )}
      </div>
    );
  }

  const detail =
    detailSelection && result ? (
      <DetailPane onClose={() => setSelection(null)}>
        <ProposalDetail
          key={detailSelection.card.id}
          card={detailSelection.card}
          spaceId={result.spaceId}
          kibanaUrl={result.kibanaUrl}
          api={api}
          reloadToken={reloadToken}
          onSelectProposal={selectFromDetail}
          renderFooterActions={(loaded, reload) => (
            <DecisionBar
              loaded={loaded}
              reload={reload}
              api={api}
              spaceId={result.spaceId}
              onDecided={() => void refresh()}
            />
          )}
        />
      </DetailPane>
    ) : null;

  return (
    <AppShell className="az-app">
      <AppHeader
        title="Alert Zero"
        leftExtras={
          result && (available || showSpace) ? (
            <div className="az-header-extras">
              {available && (
                <span
                  className={classNames("az-header-state", {
                    "az-header-state--clear": result.totalAwaitingDecision === 0,
                  })}
                >
                  {awaitingLine(result.totalAwaitingDecision)}
                </span>
              )}
              {showSpace && (
                <span className="az-badge az-badge--hollow" title="Kibana space">
                  Space: {result.spaceId}
                </span>
              )}
            </div>
          ) : undefined
        }
        actions={
          <button
            type="button"
            className={classNames("app-header-icon-btn", "az-refresh-btn", { "is-loading": loading })}
            onClick={() => void refresh()}
            disabled={loading}
            title="Refresh"
            aria-label="Refresh"
          >
            <RefreshIcon />
          </button>
        }
        fullscreen={{ isFullscreen: fullscreen.isFullscreen, onToggle: fullscreen.toggle }}
      />
      <TwoPaneLayout list={body} detail={detail} />
    </AppShell>
  );
}

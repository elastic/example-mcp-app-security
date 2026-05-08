/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useRef, useState } from "react";
import { ChevronDownIcon, LoadingState } from "../../../shared/components";
import { useClickOutside } from "../../../shared/hooks/useClickOutside";
import type { AlertContext, SecurityAlert } from "../../../shared/types";
import { AlertScoreRing, EntityIcon } from "./AlertCard";
import { ExpandSection } from "./ExpandSection";
import { FactCol } from "./FactCol";
import { NetworkTable } from "./NetworkTable";
import { ProcessTreeRow } from "./ProcessTreeRow";
import { RelatedAlertCard } from "./RelatedAlertCard";

const PROCESS_PREVIEW = 3;
const NETWORK_PREVIEW = 4;
const RELATED_PREVIEW = 3;

export interface DetailViewProps {
  alert: SecurityAlert;
  context: AlertContext | null;
  contextLoading: boolean;
  onAcknowledge: () => void;
  onCreateCase: () => void;
  onSelectAlert: (a: SecurityAlert) => void;
  onEntityFilter?: (field: string, value: string) => void;
  /** Whether the "Related alerts" panel is currently expanded — lifted to the
   * App so it survives the remount triggered by `key={selectedAlert._id}`. */
  relatedOpen: boolean;
  onToggleRelated: () => void;
}

/**
 * Right-hand pane shown when an alert is selected. Renders the score ring,
 * the Take Action menu, alert facts, rule description, and the three
 * collapsible context sections (Related / Process tree / Network).
 */
export function DetailView({
  alert,
  context,
  contextLoading,
  onAcknowledge,
  onCreateCase,
  onSelectAlert,
  onEntityFilter,
  relatedOpen,
  onToggleRelated,
}: DetailViewProps) {
  const src = alert._source;
  const sev = ((src["kibana.alert.severity"]?.toLowerCase() || "low") as "low" | "medium" | "high" | "critical");
  const score = src["kibana.alert.risk_score"] ?? 0;

  const threat = src["kibana.alert.rule.threat"]?.[0];
  const tacticName = threat?.tactic?.name;
  const techniqueId = threat?.technique?.[0]?.id;

  const userDisplay = src.user?.name
    ? (src.user.domain ? `${src.user.domain}\\${src.user.name}` : src.user.name)
    : undefined;

  const [processOpen, setProcessOpen] = useState(false);
  const [networkOpen, setNetworkOpen] = useState(false);
  const [takeActionOpen, setTakeActionOpen] = useState(false);
  const takeActionRef = useRef<HTMLDivElement | null>(null);
  useClickOutside(takeActionRef, takeActionOpen, () => setTakeActionOpen(false));

  return (
    <div className="alert-detail">
      <div className="alert-detail-top">
        <AlertScoreRing score={score} severity={sev} />
        <div className="take-action-dropdown" ref={takeActionRef}>
          <button
            type="button"
            className="alert-detail-action take-action-trigger"
            aria-haspopup="menu"
            aria-expanded={takeActionOpen}
            onClick={() => setTakeActionOpen((v) => !v)}
          >
            Take Action
            <ChevronDownIcon open={takeActionOpen} />
          </button>
          {takeActionOpen && (
            <div className="take-action-menu" role="menu">
              <button
                type="button"
                role="menuitem"
                className="take-action-option"
                onClick={() => {
                  setTakeActionOpen(false);
                  onCreateCase();
                }}
              >
                Create case now
              </button>
              <button
                type="button"
                role="menuitem"
                className="take-action-option"
                onClick={() => {
                  setTakeActionOpen(false);
                  onAcknowledge();
                }}
              >
                Acknowledge alert
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="alert-detail-head">
        {(tacticName || techniqueId) && (
          <div className="alert-card-mitre">
            {tacticName && <span className="mitre-tag mitre-tag-tactic">{tacticName}</span>}
            {techniqueId && <span className="mitre-tag mitre-tag-technique">{techniqueId}</span>}
          </div>
        )}
        <h2 className="alert-detail-title">{src["kibana.alert.rule.name"]}</h2>
        {src["kibana.alert.reason"] && (
          <div className="alert-detail-reason">{src["kibana.alert.reason"]}</div>
        )}
      </div>

      <div className="alert-detail-facts">
        <FactCol label="HOST" icon={EntityIcon.host} value={src.host?.name} field="host.name" onFilter={onEntityFilter} />
        <FactCol label="USER" icon={EntityIcon.user} value={userDisplay} filterValue={src.user?.name} field="user.name" onFilter={onEntityFilter} />
        <FactCol label="PROCESS" icon={EntityIcon.process} value={src.process?.name} field="process.name" onFilter={onEntityFilter} />
        <FactCol label="EXECUTABLE" icon={EntityIcon.executable} value={src.process?.executable} field="process.executable" onFilter={onEntityFilter} truncate />
      </div>

      {src["kibana.alert.rule.description"] && (
        <div className="alert-detail-description">
          <div className="alert-detail-description-label">Rule description</div>
          <div className="alert-detail-description-body">{src["kibana.alert.rule.description"]}</div>
        </div>
      )}

      {contextLoading ? (
        <div className="alert-detail-section"><LoadingState>Loading context...</LoadingState></div>
      ) : context ? (
        <>
          {context.relatedAlerts.length > 0 && (
            <ExpandSection
              title="Related"
              count={context.relatedAlerts.length}
              expanded={relatedOpen}
              onToggle={onToggleRelated}
              previewCount={RELATED_PREVIEW}
            >
              <div className="related-alerts-list">
                {(relatedOpen ? context.relatedAlerts : context.relatedAlerts.slice(0, RELATED_PREVIEW)).map((a) => (
                  <RelatedAlertCard
                    key={a._id}
                    alert={a}
                    selected={a._id === alert._id}
                    onClick={() => onSelectAlert(a)}
                  />
                ))}
              </div>
            </ExpandSection>
          )}

          {context.processEvents.length > 0 && (
            <ExpandSection
              title="Process tree"
              count={context.processEvents.length}
              expanded={processOpen}
              onToggle={() => setProcessOpen((v) => !v)}
              previewCount={PROCESS_PREVIEW}
            >
              <div className="process-tree-box">
                {(processOpen ? context.processEvents : context.processEvents.slice(0, PROCESS_PREVIEW)).map((e, i) => (
                  <ProcessTreeRow key={i} event={e} />
                ))}
              </div>
            </ExpandSection>
          )}

          {context.networkEvents.length > 0 && (
            <ExpandSection
              title="Network"
              count={context.networkEvents.length}
              expanded={networkOpen}
              onToggle={() => setNetworkOpen((v) => !v)}
              previewCount={NETWORK_PREVIEW}
            >
              <NetworkTable events={networkOpen ? context.networkEvents : context.networkEvents.slice(0, NETWORK_PREVIEW)} />
            </ExpandSection>
          )}
        </>
      ) : null}
    </div>
  );
}

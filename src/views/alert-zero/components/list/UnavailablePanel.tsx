/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import {
  spacePrefix,
  type AlertZeroAvailabilityState,
  type AlertZeroStatus,
} from "../../../../shared/alert-zero-types";
import { StatePanel } from "./StatePanel";

export const UNAVAILABLE_TITLE: Record<AlertZeroAvailabilityState, string> = {
  enabled: "Alert Zero is unavailable",
  plugin_disabled: "Alert Zero isn't installed",
  disabled_in_space: "Alert Zero is off in this space",
  space_not_found: "Space not found",
  license: "Enterprise license required",
  serverless_tier: "Security Complete tier required",
  missing_privileges: "Missing privileges",
  dependencies_unavailable: "Alert Zero dependencies are unavailable",
  unreachable: "Can't reach Kibana",
};

export function advancedSettingsUrl(kibanaUrl: string, spaceId: string): string {
  return `${kibanaUrl}${spacePrefix(spaceId)}/app/management/kibana/settings?query=enableAlertZero`;
}

export interface UnavailablePanelProps {
  readonly status: AlertZeroStatus;
  readonly spaceId: string;
  readonly kibanaUrl: string;
  readonly checking: boolean;
  readonly onCheckAgain: () => void;
  readonly onOpenLink: (url: string) => void;
}

export function UnavailablePanel({
  status,
  spaceId,
  kibanaUrl,
  checking,
  onCheckAgain,
  onOpenLink,
}: UnavailablePanelProps) {
  return (
    <StatePanel
      title={UNAVAILABLE_TITLE[status.state] ?? UNAVAILABLE_TITLE.enabled}
      actions={
        <>
          {status.state === "disabled_in_space" && (
            <button
              type="button"
              className="az-list-btn az-list-btn--primary"
              onClick={() => onOpenLink(advancedSettingsUrl(kibanaUrl, spaceId))}
            >
              Open Advanced Settings
            </button>
          )}
          <button type="button" className="az-list-btn" onClick={onCheckAgain} disabled={checking}>
            {checking ? "Checking…" : "Check again"}
          </button>
        </>
      }
    >
      <p className="az-state-text">{status.reason}</p>
      {status.remediation && (
        <p className="az-state-text az-state-remediation">{status.remediation}</p>
      )}
      <dl className="az-state-facts">
        <dt>Space</dt>
        <dd>{spaceId}</dd>
        {status.httpStatus !== undefined && (
          <>
            <dt>HTTP status</dt>
            <dd>{status.httpStatus}</dd>
          </>
        )}
      </dl>
    </StatePanel>
  );
}

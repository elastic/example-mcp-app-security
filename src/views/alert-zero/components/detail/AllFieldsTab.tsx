/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from "react";
import {
  PROPOSAL_FIELD_KEYS,
  type AlertZeroInvestigation,
  type AlertZeroProposalDetail,
} from "../../../../shared/alert-zero-types";
import { useDetailContext } from "./DetailContext";
import { FIELD_COVERAGE, getUnmappedFields, isKnownProposalField } from "./fieldCoverage";
import { safeJson } from "./helpers";
import { DownloadIcon } from "./icons";
import { Callout, CopyButton, KeyValueTree, Section } from "./primitives";

export interface AllFieldsTabProps {
  readonly detail: AlertZeroProposalDetail;
  readonly investigation?: AlertZeroInvestigation;
  readonly investigationError?: string;
}

const CONVERSATION_COLLECTIONS = ["rounds", "events", "attachments", "metadata"];
const DETAIL_PROPOSAL_KEY = "proposal";
const INVESTIGATION_CONVERSATION_KEY = "conversation";

function CoverageTag({ name }: { readonly name: string }) {
  if (!isKnownProposalField(name)) return null;
  return (
    <span className="azd-coverage" title="Where this field is shown">
      → {FIELD_COVERAGE[name]}
    </span>
  );
}

export function AllFieldsTab({ detail, investigation, investigationError }: AllFieldsTabProps) {
  const { api } = useDetailContext();
  const proposal = detail.proposal as unknown as Record<string, unknown>;
  const present = PROPOSAL_FIELD_KEYS.filter((k) => proposal[k] !== undefined);
  const notSet = PROPOSAL_FIELD_KEYS.filter((k) => proposal[k] === undefined);
  const unmapped = getUnmappedFields(proposal);
  const conversation = investigation?.conversation as Record<string, unknown> | undefined;
  const json = useMemo(() => safeJson({ detail, investigation }), [detail, investigation]);

  const detailEntries = Object.entries(detail as unknown as Record<string, unknown>).filter(([k]) => k !== DETAIL_PROPOSAL_KEY);
  const conversationTop = conversation ? Object.entries(conversation).filter(([k]) => !CONVERSATION_COLLECTIONS.includes(k)) : [];
  const conversationCollections = conversation
    ? CONVERSATION_COLLECTIONS.filter((k) => k !== "metadata" && conversation[k] !== undefined).map((k) => [k, conversation[k]] as const)
    : [];
  const investigationExtras = investigation
    ? Object.entries(investigation as unknown as Record<string, unknown>).filter(([k]) => k !== INVESTIGATION_CONVERSATION_KEY)
    : [];

  return (
    <div className="azd-tab-body">
      <div className="azd-allfields-bar">
        <span className="azd-muted azd-small">Every field the server returned, labelled with where it&apos;s shown.</span>
        <span className="azd-allfields-actions">
          <CopyButton text={json} label="all as JSON" showLabel />
          <button
            type="button"
            className="azd-btn azd-btn--sm"
            onClick={() =>
              api.downloadFile({
                filename: `alert-zero-proposal-${detail.proposal.id}.json`,
                mimeType: "application/json",
                text: json,
              })
            }
          >
            <DownloadIcon /> Download JSON
          </button>
        </span>
      </div>

      <Section title="Proposal" count={present.length}>
        <KeyValueTree entries={present.map((k) => [k, proposal[k]] as const)} annotate={(k) => <CoverageTag name={k} />} openDepth={1} />
        {notSet.length > 0 && (
          <div className="azd-muted azd-small azd-notset">
            Not set: <code className="azd-mono">{notSet.join(", ")}</code>
          </div>
        )}
      </Section>

      <Section title="Other fields" count={unmapped.length}>
        {unmapped.length === 0 ? (
          <div className="azd-muted">None — every proposal field is shown in a section of the Proposal tab.</div>
        ) : (
          <>
            <div className="azd-muted azd-small">Fields the server returned that this view doesn&apos;t know yet. They are only shown here.</div>
            <KeyValueTree entries={unmapped.map((k) => [k, proposal[k]] as const)} openDepth={2} />
          </>
        )}
      </Section>

      <Section title="Detail response">
        <KeyValueTree entries={detailEntries} openDepth={0} />
      </Section>

      {investigation ? (
        <>
          <Section title="Conversation">
            <KeyValueTree entries={[...conversationTop, ...conversationCollections]} openDepth={1} />
          </Section>
          <Section title="Conversation metadata">
            {investigation.conversation.metadata ? (
              <KeyValueTree entries={Object.entries(investigation.conversation.metadata)} openDepth={2} />
            ) : (
              <div className="azd-muted">No metadata.</div>
            )}
          </Section>
          <Section title="Investigation response">
            <KeyValueTree entries={investigationExtras} openDepth={0} />
          </Section>
        </>
      ) : (
        investigationError && (
          <Callout tone="warning" title="Conversation fields unavailable">
            {investigationError}
          </Callout>
        )
      )}
    </div>
  );
}

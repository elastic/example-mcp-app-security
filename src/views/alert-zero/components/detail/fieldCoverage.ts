/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { PROPOSAL_FIELD_KEYS } from "../../../../shared/alert-zero-types";

export type ProposalFieldKey = (typeof PROPOSAL_FIELD_KEYS)[number];

/** Separator between labels when a field renders in more than one section. */
export const COVERAGE_SEPARATOR = " · ";

/**
 * Where each proposal field is rendered in the detail pane. Labels match the
 * `data-section` attributes of the header and Proposal-tab sections; the
 * render test asserts each field's value appears inside every listed section.
 */
export const FIELD_COVERAGE: Record<ProposalFieldKey, string> = {
  id: "Provenance",
  spaceId: "Provenance",
  conversationId: "Provenance",
  title: "Header",
  comment: "Why",
  actionWorkflowId: "What happens if you approve",
  actionInput: "What happens if you approve",
  status: "Header · Provenance",
  decision: "Outcome",
  supersededBy: "Outcome · Lineage",
  rootProposalId: "Lineage",
  supersedes: "Lineage",
  revision: "Lineage",
  impact: "Header",
  confidence: "Header",
  category: "Header",
  origin: "Provenance",
  expiresAt: "Header · Provenance",
  decidedBy: "Outcome",
  decidedAt: "Outcome",
  dismissReason: "Outcome",
  rationale: "Outcome",
  executionError: "Outcome",
  previousExecutionError: "Previous attempt",
  workflowExecutionId: "Provenance",
  createdAt: "Provenance",
  createdBy: "Provenance",
  action: "What happens if you approve",
  conversationTitle: "Header · Investigation",
  conversationAgentId: "Investigation",
  conversationAssignees: "Investigation",
  entityIds: "Investigation",
};

export function coverageSections(key: ProposalFieldKey): string[] {
  return FIELD_COVERAGE[key].split(COVERAGE_SEPARATOR);
}

const KNOWN = new Set<string>(PROPOSAL_FIELD_KEYS);

export function isKnownProposalField(key: string): key is ProposalFieldKey {
  return KNOWN.has(key);
}

/** Top-level keys the contract does not know about (fields the server added later). */
export function getUnmappedFields(obj: Record<string, unknown>): string[] {
  return Object.keys(obj).filter((k) => !KNOWN.has(k));
}

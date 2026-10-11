/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ReactNode } from "react";
import type {
  AlertZeroInvestigation,
  AlertZeroProposalCard,
  AlertZeroProposalDetail,
} from "../../shared/alert-zero-types";
import type { AlertZeroApi } from "./api";

/** Data the detail pane has loaded, handed to the footer slot. */
export interface LoadedProposalDetail {
  readonly detail: AlertZeroProposalDetail;
  readonly investigation?: AlertZeroInvestigation;
}

/** Props for `components/detail/ProposalDetail.tsx`, rendered by `App.tsx`. */
export interface ProposalDetailProps {
  /** Selected list row, so the header renders before the detail call returns. */
  readonly card: AlertZeroProposalCard;
  readonly spaceId: string;
  readonly kibanaUrl: string;
  readonly api: AlertZeroApi;
  /** Bumped by the parent to force a reload (e.g. after a decision). */
  readonly reloadToken?: number;
  /**
   * Navigate to another proposal (sibling or revision). Build the card with
   * `toProposalCard` from `shared/alert-zero-types`.
   */
  readonly onSelectProposal?: (card: AlertZeroProposalCard) => void;
  /**
   * Footer slot for decision controls (Approve / Decline). Receives the
   * loaded detail and a reload callback. Rendered above the link buttons.
   */
  readonly renderFooterActions?: (loaded: LoadedProposalDetail, reload: () => void) => ReactNode;
}

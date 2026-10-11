/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createContext, useContext } from "react";
import type {
  ConversationAttachment,
  EnrichedAlert,
  ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";
import type { AlertZeroApi } from "../../api";

export interface DetailContextValue {
  readonly api: AlertZeroApi;
  readonly currentProposalId: string;
  /** Current proposal, its revision chain, and siblings. */
  readonly proposalsById: ReadonlyMap<string, ProposalWithMetadata>;
  readonly attachmentsById: ReadonlyMap<string, ConversationAttachment>;
  readonly alerts: Readonly<Record<string, EnrichedAlert>>;
  /** Undefined when the host gave no `onSelectProposal`. */
  readonly selectProposal?: (id: string) => void;
  /** Switch to the Evidence tab and highlight an attachment. */
  readonly jumpToAttachment: (id: string) => void;
}

const noop = () => undefined;

const DEFAULT_CONTEXT: DetailContextValue = {
  api: {
    callTool: () => Promise.reject(new Error("No API")),
    openLink: noop,
    sendMessage: noop,
    downloadFile: noop,
  },
  currentProposalId: "",
  proposalsById: new Map(),
  attachmentsById: new Map(),
  alerts: {},
  jumpToAttachment: noop,
};

export const DetailContext = createContext<DetailContextValue>(DEFAULT_CONTEXT);

export function useDetailContext(): DetailContextValue {
  return useContext(DetailContext);
}

export function lookupAlert(
  alerts: Readonly<Record<string, EnrichedAlert>>,
  id: string,
): EnrichedAlert | undefined {
  return alerts[id] ?? (id.includes(":") ? alerts[id.split(":")[0]] : undefined);
}

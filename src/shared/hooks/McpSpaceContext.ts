/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createContext } from "react";
import type { SpaceSummary } from "../spaces.js";

/**
 * Kibana space state owned by `<McpAppProvider>`.
 *
 * Kept separate from `McpAppContext` so stubbed contexts in tests don't need
 * space fields. Without a provider (or when `list-spaces` fails) `spaces` is
 * empty and every space UI stays hidden.
 */
export interface McpSpaceContextValue {
  /** Space from the cluster config; empty until `list-spaces` resolves. */
  readonly configured: string;
  /** Space the view is showing for this session. */
  readonly active: string;
  /** Spaces the API key can access. */
  readonly spaces: readonly SpaceSummary[];
  /**
   * Show `id` for the rest of the session: tells the model, then remounts
   * the view so it reloads in that space.
   */
  readonly setActiveSpace: (id: string) => Promise<void>;
}

export const NO_SPACES: McpSpaceContextValue = {
  configured: "",
  active: "",
  spaces: [],
  setActiveSpace: async () => {},
};

export const McpSpaceContext = createContext<McpSpaceContextValue>(NO_SPACES);

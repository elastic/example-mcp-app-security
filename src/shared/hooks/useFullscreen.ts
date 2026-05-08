/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useState } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";

export interface FullscreenState {
  isFullscreen: boolean;
  toggle: () => void;
}

/**
 * Wraps the host's `requestDisplayMode({ mode: "fullscreen" | "inline" })`
 * call together with local React state, so views can render a single icon
 * button without copy-pasting the toggle handler.
 */
export function useFullscreen(getApp: () => McpApp | null): FullscreenState {
  const [isFullscreen, setIsFullscreen] = useState(false);

  const toggle = useCallback(() => {
    const next = !isFullscreen;
    try {
      getApp()?.requestDisplayMode({ mode: next ? "fullscreen" : "inline" });
    } catch {
      /* ignore — host may not support display mode requests */
    }
    setIsFullscreen(next);
  }, [getApp, isFullscreen]);

  return { isFullscreen, toggle };
}

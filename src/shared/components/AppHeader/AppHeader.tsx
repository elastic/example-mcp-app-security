/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { AppGlyph, ExitFullscreenIcon, FullscreenIcon } from "../icons/icons";
import "./AppHeader.css";

export interface AppHeaderProps {
  /** Title text rendered next to the AppGlyph. */
  title: string;
  /** Optional content rendered immediately after the brand — query pills, status tabs, filter pills. */
  leftExtras?: React.ReactNode;
  /** Optional content rendered before the fullscreen toggle — search input, refresh, custom buttons. */
  actions?: React.ReactNode;
  /** When provided, a fullscreen toggle button is appended to the right side. */
  fullscreen?: { isFullscreen: boolean; onToggle: () => void };
}

/**
 * Standard app header: brand (glyph + title) on the left, action slot + a
 * fullscreen toggle on the right. Replaces every `.{view}-header*` class.
 */
export function AppHeader({ title, leftExtras, actions, fullscreen }: AppHeaderProps) {
  return (
    <header className="app-header">
      <div className="app-header-left">
        <div className="app-header-brand">
          <span className="app-header-glyph" aria-hidden="true"><AppGlyph /></span>
          <h1 className="app-header-title">{title}</h1>
        </div>
        {leftExtras}
      </div>
      <div className="app-header-actions">
        {actions}
        {fullscreen && (
          <button
            type="button"
            className="app-header-icon-btn"
            onClick={fullscreen.onToggle}
            title={fullscreen.isFullscreen ? "Exit fullscreen" : "Fullscreen"}
            aria-label={fullscreen.isFullscreen ? "Exit fullscreen" : "Fullscreen"}
          >
            {fullscreen.isFullscreen ? <ExitFullscreenIcon /> : <FullscreenIcon />}
          </button>
        )}
      </div>
    </header>
  );
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { CloseIcon } from "../icons/icons";
import "./DetailPane.css";

export interface DetailPaneProps {
  children: React.ReactNode;
  /** When provided, renders a close button in the top-right corner. */
  onClose?: () => void;
  /** Apply the elevated surface (lighter background + left border). */
  elevated?: boolean;
  className?: string;
}

/**
 * Convenience wrapper for the right-hand detail content. Sits inside the
 * `<TwoPaneLayout detail={…}>` slot.
 */
export function DetailPane({ children, onClose, elevated, className }: DetailPaneProps) {
  const cls = ["detail-pane-content", elevated ? "elevated" : "", className ?? ""]
    .filter(Boolean)
    .join(" ");
  return (
    <div className={cls}>
      {onClose && (
        <button
          type="button"
          className="detail-pane-close"
          onClick={onClose}
          aria-label="Close details"
        >
          <CloseIcon size={14} />
        </button>
      )}
      {children}
    </div>
  );
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { CloseIcon } from "../icons/icons";
import "./Toast.css";

export type ToastTone = "info" | "success" | "danger";

export interface ToastInput {
  /** Human-readable toast message. */
  message: React.ReactNode;
  /** Visual tone — drives the left border + icon color. Default `info`. */
  tone?: ToastTone;
  /** Auto-dismiss duration in milliseconds. Set to 0 to disable. Default 8000. */
  durationMs?: number;
  /** Action label — when present a button is rendered (e.g. "Undo"). */
  actionLabel?: string;
  /** Called when the user clicks the action button. The toast auto-dismisses afterwards. */
  onAction?: () => void;
}

interface ActiveToast extends ToastInput {
  id: number;
}

interface ToastApi {
  /** Show a toast and return its id (so callers can dismiss it manually). */
  show: (toast: ToastInput) => number;
  /** Remove a toast by id. No-op if the toast already disappeared. */
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const TONE_GLYPH: Record<ToastTone, string> = {
  info: "i",
  success: "\u2713",
  danger: "!",
};

export interface ToastProviderProps {
  children: React.ReactNode;
}

/**
 * Wrap a view's tree with this provider once (typically just inside the
 * top-level component) and call `useToast()` from anywhere underneath.
 *
 * Toasts render into a portal anchored to `document.body` so they aren't
 * clipped by container overflow / transform.
 */
export function ToastProvider({ children }: ToastProviderProps) {
  const [toasts, setToasts] = useState<ActiveToast[]>([]);
  const idRef = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const show = useCallback((input: ToastInput): number => {
    idRef.current += 1;
    const id = idRef.current;
    setToasts((prev) => [...prev, { ...input, id }]);
    return id;
  }, []);

  const api = useMemo<ToastApi>(() => ({ show, dismiss }), [show, dismiss]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return ctx;
}

function ToastStack({ toasts, onDismiss }: { toasts: ActiveToast[]; onDismiss: (id: number) => void }) {
  if (typeof document === "undefined") return null;
  return createPortal(
    <div className="toast-stack" role="region" aria-live="polite" aria-label="Notifications">
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>,
    document.body,
  );
}

function ToastItem({ toast, onDismiss }: { toast: ActiveToast; onDismiss: (id: number) => void }) {
  const { id, message, tone = "info", durationMs = 8000, actionLabel, onAction } = toast;

  // Bind the per-toast dismiss to a ref so the auto-dismiss `useEffect` can
  // depend on `id` only. Otherwise every re-render of `ToastStack` (e.g. when
  // *another* toast is added/removed) would create a new arrow function,
  // change the dep array, clear the existing timer, and start a fresh
  // 8-second countdown — toasts would never auto-dismiss in a busy UI.
  const onDismissRef = useRef(onDismiss);
  onDismissRef.current = onDismiss;
  const dismissThis = useCallback(() => {
    onDismissRef.current(id);
  }, [id]);

  useEffect(() => {
    if (!durationMs) return;
    const timer = setTimeout(dismissThis, durationMs);
    return () => clearTimeout(timer);
  }, [durationMs, dismissThis]);

  return (
    <div className={`toast toast-tone-${tone}`} role="status">
      <span className="toast-icon" aria-hidden="true">{TONE_GLYPH[tone]}</span>
      <div className="toast-message">{message}</div>
      {actionLabel && onAction && (
        <button
          type="button"
          className="toast-action"
          onClick={() => {
            onAction();
            dismissThis();
          }}
        >
          {actionLabel}
        </button>
      )}
      <button
        type="button"
        className="toast-close"
        onClick={dismissThis}
        aria-label="Dismiss notification"
      >
        <CloseIcon />
      </button>
    </div>
  );
}

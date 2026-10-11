/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useId, useRef } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export interface DecisionDialogProps {
  readonly title: React.ReactNode;
  readonly onClose: () => void;
  /** While true, Esc and outside clicks are ignored. */
  readonly busy?: boolean;
  readonly footer: React.ReactNode;
  readonly children: React.ReactNode;
  readonly className?: string;
}

/**
 * Lightweight modal rendered into `document.body` so it covers the whole
 * iframe regardless of the detail pane's scroll position. Focuses the
 * `[data-autofocus]` control (or the first focusable one) and restores focus
 * to the trigger on close.
 */
export function DecisionDialog({ title, onClose, busy = false, footer, children, className }: DecisionDialogProps) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const busyRef = useRef(busy);
  busyRef.current = busy;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const target =
      dialog?.querySelector<HTMLElement>("[data-autofocus]") ?? dialog?.querySelector<HTMLElement>(FOCUSABLE) ?? dialog;
    target?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        if (!busyRef.current) onCloseRef.current();
        return;
      }
      if (e.key !== "Tab" || !dialog) return;
      const items = [...dialog.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || !dialog.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !dialog.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      if (previous?.isConnected) previous.focus();
    };
  }, []);

  if (typeof document === "undefined") return null;
  return createPortal(
    <div
      className="azdec-overlay"
      data-testid="azdec-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busyRef.current) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className={className ? `azdec-dialog ${className}` : "azdec-dialog"}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-busy={busy || undefined}
        tabIndex={-1}
      >
        <header className="azdec-dialog-head">
          <h2 id={titleId} className="azdec-dialog-title">
            {title}
          </h2>
        </header>
        <div className="azdec-dialog-body">{children}</div>
        <footer className="azdec-dialog-foot">{footer}</footer>
      </div>
    </div>,
    document.body,
  );
}

export function Spinner() {
  return <span className="azdec-spinner" aria-hidden="true" />;
}

export interface RationaleFieldProps {
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly label: string;
  readonly hint?: string;
  readonly placeholder?: string;
  readonly required?: boolean;
  readonly error?: string;
  readonly disabled?: boolean;
  readonly autoFocus?: boolean;
  readonly max: number;
}

export function RationaleField({
  value,
  onChange,
  label,
  hint,
  placeholder,
  required = false,
  error,
  disabled = false,
  autoFocus = false,
  max,
}: RationaleFieldProps) {
  const id = useId();
  const errorId = `${id}-error`;
  const counterId = `${id}-counter`;
  return (
    <div className="azdec-field">
      <label className="azdec-label" htmlFor={id}>
        {label}
        {hint && <span className="azdec-label-hint"> {hint}</span>}
      </label>
      <textarea
        id={id}
        className="azdec-textarea"
        value={value}
        rows={3}
        maxLength={max}
        placeholder={placeholder}
        disabled={disabled}
        aria-required={required || undefined}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${errorId} ${counterId}` : counterId}
        data-autofocus={autoFocus || undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      <div className="azdec-field-foot">
        {error && (
          <span id={errorId} className="azdec-field-error">
            {error}
          </span>
        )}
        <span id={counterId} className={value.length > max * 0.9 ? "azdec-counter is-near" : "azdec-counter"}>
          {value.length.toLocaleString("en-US")} / {max.toLocaleString("en-US")}
        </span>
      </div>
    </div>
  );
}

export function InlineError({ message, detail }: { readonly message: string; readonly detail?: string }) {
  return (
    <div className="azdec-error" role="alert">
      <span>{message}</span>
      {detail && detail !== message && <span className="azdec-error-detail">{detail}</span>}
    </div>
  );
}

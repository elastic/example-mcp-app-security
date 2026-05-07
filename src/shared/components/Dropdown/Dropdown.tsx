/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useRef, useState } from "react";
import { ChevronDownIcon } from "../icons/icons";
import { useClickOutside } from "../../hooks/useClickOutside";
import "./Dropdown.css";

export interface DropdownOption<V extends string> {
  value: V;
  label: string;
}

export interface DropdownProps<V extends string> {
  /** Static prefix shown before the selected value, e.g. "Sort by:". */
  label: string;
  options: DropdownOption<V>[];
  value: V;
  onChange: (value: V) => void;
  /** Anchor the menu to the trigger's right edge instead of its left. */
  align?: "left" | "right";
  ariaLabel?: string;
}

/**
 * Click-outside-aware sort/group/status dropdown used across every list view.
 * Replaces the open-coded `*-list-subheader-sort*` triplet (trigger + menu +
 * option button) plus its companion `useEffect(mousedown)` listener.
 */
export function Dropdown<V extends string>({
  label,
  options,
  value,
  onChange,
  align = "left",
  ariaLabel,
}: DropdownProps<V>) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);
  useClickOutside(ref, open, () => setOpen(false));

  const active = options.find((o) => o.value === value);

  return (
    <div className="dropdown" ref={ref}>
      <button
        type="button"
        className="dropdown-trigger"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
      >
        <span>
          {label} <span className="dropdown-trigger-value">{active?.label}</span>
        </span>
        <ChevronDownIcon open={open} />
      </button>
      {open && (
        <div className={`dropdown-menu${align === "right" ? " align-right" : ""}`} role="listbox">
          {options.map((opt) => (
            <button
              key={opt.value}
              type="button"
              role="option"
              aria-selected={opt.value === value}
              className={`dropdown-option${opt.value === value ? " active" : ""}`}
              onClick={() => {
                onChange(opt.value);
                setOpen(false);
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

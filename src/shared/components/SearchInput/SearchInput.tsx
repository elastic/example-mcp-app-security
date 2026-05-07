/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { SearchIcon } from "../icons/icons";
import "./SearchInput.css";

export interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
  /** Fires on Enter. */
  onSubmit?: (value: string) => void;
  /** Fires on Escape — also clears `value` to an empty string via `onChange`. */
  onClear?: () => void;
  placeholder?: string;
  ariaLabel?: string;
}

/** 366px header search input with the standard search icon and focus border. */
export function SearchInput({
  value,
  onChange,
  onSubmit,
  onClear,
  placeholder = "Filter",
  ariaLabel,
}: SearchInputProps) {
  return (
    <div className="search-input">
      <SearchIcon />
      <input
        type="text"
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") onSubmit?.(value);
          if (e.key === "Escape") {
            onChange("");
            onClear?.();
          }
        }}
      />
    </div>
  );
}

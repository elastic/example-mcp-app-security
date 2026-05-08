/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./ListSubheader.css";

export interface ListSubheaderProps {
  /** Left-side count + sort dropdown content. */
  left?: React.ReactNode;
  /** Right-side controls (toggles, group dropdown). */
  right?: React.ReactNode;
}

/**
 * "Showing N alerts — Sort by — Group by — Details" bar.
 * Compose with `<Dropdown>` and `<ToggleSwitch>` for the actual controls.
 */
export function ListSubheader({ left, right }: ListSubheaderProps) {
  return (
    <div className="list-subheader">
      <div className="list-subheader-left">{left}</div>
      <div className="list-subheader-controls">{right}</div>
    </div>
  );
}

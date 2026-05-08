/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import "./ToggleSwitch.css";

export interface ToggleSwitchProps {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  ariaLabel?: string;
}

export function ToggleSwitch({ label, checked, onChange, ariaLabel }: ToggleSwitchProps) {
  return (
    <label className="toggle-switch-label">
      <span>{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabel ?? label}
        className={classNames("toggle-switch", { on: checked })}
        onClick={() => onChange(!checked)}
      >
        <span className="toggle-switch-thumb" />
      </button>
    </label>
  );
}

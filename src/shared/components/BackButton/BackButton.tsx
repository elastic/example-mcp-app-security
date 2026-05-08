/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./BackButton.css";

export interface BackButtonProps {
  onClick: () => void;
  label?: string;
}

export function BackButton({ onClick, label = "Back to list" }: BackButtonProps) {
  return (
    <button type="button" className="back-button" onClick={onClick}>
      <span aria-hidden="true">&larr;</span> {label}
    </button>
  );
}

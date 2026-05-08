/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";

export interface FactColProps {
  label: string;
  value?: string;
  /** Overrides `value` when building the filter query (e.g. bare user.name without the `DOMAIN\` prefix). */
  filterValue?: string;
  field?: string;
  onFilter?: (field: string, value: string) => void;
  truncate?: boolean;
  icon?: React.ReactNode;
}

/** Single fact column inside the alert-detail header (host/user/process/executable). */
export function FactCol({ label, value, filterValue, field, onFilter, truncate, icon }: FactColProps) {
  const displayed = value || "—";
  const canFilter = !!(onFilter && field && (filterValue ?? value));
  const classes = classNames("alert-detail-fact-value", { truncate, clickable: canFilter });

  return (
    <div className="alert-detail-fact">
      <div className="alert-detail-fact-label">
        {icon && <span className="alert-detail-fact-icon" aria-hidden="true">{icon}</span>}
        <span>{label}</span>
      </div>
      {canFilter ? (
        <button
          type="button"
          className={classes}
          title={`Filter by ${field}: ${filterValue ?? value}`}
          onClick={() => onFilter!(field!, filterValue ?? value!)}
        >
          {displayed}
        </button>
      ) : (
        <div className={classes} title={value || undefined}>{displayed}</div>
      )}
    </div>
  );
}

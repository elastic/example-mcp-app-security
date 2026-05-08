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
  truncate?: boolean;
  entities?: { type: string; value: string }[];
  onEntityClick?: (type: string, value: string, x: number, y: number) => void;
}

/** Single fact column inside the attack-discovery detail header. */
export function FactCol({ label, value, truncate, entities, onEntityClick }: FactColProps) {
  const hasEntities = entities && entities.length > 0 && onEntityClick;
  const valueClass = classNames("discovery-detail-fact-value", { truncate });
  return (
    <div className="discovery-detail-fact">
      <div className="discovery-detail-fact-label">{label}</div>
      {hasEntities ? (
        <div className={valueClass} title={value || undefined}>
          {entities.map((e, i) => (
            <React.Fragment key={`${e.type}:${e.value}`}>
              {i > 0 && <span className="discovery-detail-fact-sep">, </span>}
              <button
                type="button"
                className="discovery-detail-fact-entity"
                onClick={(ev) => {
                  ev.stopPropagation();
                  const r = (ev.currentTarget as HTMLElement).getBoundingClientRect();
                  onEntityClick(e.type, e.value, r.left, r.bottom + 6);
                }}
                title={`${e.type}: ${e.value}`}
              >
                {e.value}
              </button>
            </React.Fragment>
          ))}
        </div>
      ) : (
        <div className={valueClass} title={value || undefined}>
          {value || "—"}
        </div>
      )}
    </div>
  );
}

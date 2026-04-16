/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import type { MitreThreat } from "./types";

export function MitreTags({ threats }: { threats?: MitreThreat[] }) {
  if (!threats?.length) return null;

  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
      {threats.map((t, i) => (
        <React.Fragment key={i}>
          <span className="mitre-tag mitre-tactic">{t.tactic.name}</span>
          {t.technique?.map((tech) => (
            <span key={tech.id} className="mitre-tag mitre-technique">
              {tech.id} {tech.name}
            </span>
          ))}
        </React.Fragment>
      ))}
    </div>
  );
}

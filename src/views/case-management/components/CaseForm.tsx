/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from "react";
import { SeverityBadge } from "../../../shared/severity";

interface CaseFormProps {
  onSubmit: (data: { title: string; description: string; tags: string; severity: string }) => void;
}

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

export function CaseForm({ onSubmit }: CaseFormProps) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [severity, setSeverity] = useState<string>("low");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    onSubmit({ title: title.trim(), description: description.trim(), tags, severity });
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Create security case</h2>

      <div className="form-field">
        <label htmlFor="case-title">Title</label>
        <input
          id="case-title"
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Short, actionable title"
          required
          autoComplete="off"
        />
      </div>

      <div className="form-field">
        <label htmlFor="case-desc">Description</label>
        <textarea
          id="case-desc"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Scope, affected assets, initial findings, links…"
        />
      </div>

      <div className="form-field">
        <span className="case-sev-label" id="case-sev-label">
          Severity
        </span>
        <div
          className="case-form-severity-row"
          role="group"
          aria-labelledby="case-sev-label"
        >
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              className={`case-severity-option ${severity === s ? "active" : ""}`}
              onClick={() => setSeverity(s)}
            >
              <SeverityBadge severity={s} />
            </button>
          ))}
        </div>
      </div>

      <div className="form-field">
        <label htmlFor="case-tags">Tags</label>
        <input
          id="case-tags"
          type="text"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          placeholder="Comma-separated, e.g. malware, IR-2025, mitre:T1059"
          autoComplete="off"
        />
      </div>

      <div className="case-form-actions">
        <button type="submit" className="btn btn-primary" disabled={!title.trim()}>
          Create case
        </button>
      </div>
    </form>
  );
}

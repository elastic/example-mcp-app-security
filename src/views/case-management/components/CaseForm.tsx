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
  onCancel?: () => void;
}

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

export function CaseForm({ onSubmit, onCancel }: Readonly<CaseFormProps>) {
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
    <form className="case-form" onSubmit={handleSubmit} noValidate>
      <header className="case-form-header">
        <h2 className="case-form-title">Create security case</h2>
        <p className="case-form-subtitle">
          Track an investigation, attach alerts, and collaborate with your team.
        </p>
      </header>

      <section className="case-form-section">
        <div className="case-form-section-head">
          <span className="case-form-step" aria-hidden="true">1</span>
          <h3 className="case-form-section-title">Case fields</h3>
        </div>

        <div className="case-form-grid">
          <div className="form-field">
            <div className="form-field-label">
              <label htmlFor="case-title">Name</label>
              <span className="form-field-required">Required</span>
            </div>
            <input
              id="case-title"
              className="form-input"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Short, actionable title"
              required
              autoComplete="off"
            />
          </div>

          <fieldset className="form-field form-fieldset">
            <legend className="form-field-label">
              <span>Severity</span>
            </legend>
            <div className="case-form-severity-row">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`case-severity-option ${severity === s ? "active" : ""}`}
                  onClick={() => setSeverity(s)}
                  aria-pressed={severity === s}
                >
                  <SeverityBadge severity={s} />
                </button>
              ))}
            </div>
          </fieldset>

          <div className="form-field">
            <div className="form-field-label">
              <label htmlFor="case-tags">Tags</label>
              <span className="form-field-optional">Optional</span>
            </div>
            <input
              id="case-tags"
              className="form-input"
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="malware, IR-2025, mitre:T1059"
              autoComplete="off"
            />
            <p className="form-field-helper">Comma-separated.</p>
          </div>

          <div className="form-field">
            <div className="form-field-label">
              <label htmlFor="case-desc">Description</label>
              <span className="form-field-optional">Optional</span>
            </div>
            <textarea
              id="case-desc"
              className="form-textarea"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Scope, affected assets, initial findings, links…"
              rows={6}
            />
          </div>
        </div>
      </section>

      <footer className="case-form-actions">
        {onCancel && (
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onCancel}
          >
            Cancel
          </button>
        )}
        <button
          type="submit"
          className="btn btn-primary"
          disabled={!title.trim()}
        >
          Create case
        </button>
      </footer>
    </form>
  );
}

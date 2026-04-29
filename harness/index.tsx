/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Harness catalogue — the landing page listing every view as a preview tile.
 *
 * Each tile embeds the view in an iframe so changes hot-reload without losing
 * layout context. Click a tile to open the view full-window.
 */

import React, { useState } from "react";
import { createRoot } from "react-dom/client";

type Tile = {
  slug: string;
  title: string;
  blurb: string;
  variants?: { label: string; query: string }[];
};

const VIEWS: Tile[] = [
  {
    slug: "alert-triage",
    title: "Alert Triage",
    blurb: "Prioritised alerts with MITRE tags, severity bars, and the process/user fact box.",
    variants: [
      { label: "Default", query: "" },
      { label: "Empty", query: "?fixture=empty" },
    ],
  },
  {
    slug: "case-management",
    title: "Case Management",
    blurb: "Browse / detail / create cases with KPI strip and severity panel.",
    variants: [
      { label: "Default", query: "" },
      { label: "Empty", query: "?fixture=empty" },
    ],
  },
  {
    slug: "detection-rules",
    title: "Detection Rules",
    blurb: "Rule list with severity · type · language · tag grouping, plus noisy-rules panel.",
    variants: [
      { label: "Default", query: "" },
      { label: "Empty", query: "?fixture=empty" },
    ],
  },
  {
    slug: "attack-discovery",
    title: "Attack Discovery",
    blurb: "Generated multi-alert narratives with entity/rule signals and group-by controls.",
    variants: [
      { label: "Default", query: "" },
      { label: "Generating", query: "?fixture=generating" },
      { label: "Empty", query: "?fixture=empty" },
    ],
  },
  {
    slug: "sample-data",
    title: "Sample Data",
    blurb: "Pick scenarios and generate sample events + alerts.",
    variants: [
      { label: "Default", query: "" },
      { label: "Empty cluster", query: "?fixture=empty" },
    ],
  },
  {
    slug: "threat-hunt",
    title: "Threat Hunt",
    blurb: "ES|QL console + entity graph investigation.",
    variants: [
      { label: "Default", query: "" },
      { label: "Empty result", query: "?fixture=empty" },
    ],
  },
];

function viewUrl(slug: string, query = ""): string {
  return `/src/views/${slug}/mcp-app.html${query}`;
}

function ViewTile({ tile }: { tile: Tile }) {
  const [variant, setVariant] = useState(tile.variants?.[0] ?? { label: "Default", query: "" });
  const src = viewUrl(tile.slug, variant.query);
  return (
    <article className="tile">
      <header className="tile-header">
        <div className="tile-title-group">
          <h2 className="tile-title">{tile.title}</h2>
          <p className="tile-blurb">{tile.blurb}</p>
        </div>
        <div className="tile-actions">
          {tile.variants && tile.variants.length > 1 && (
            <div className="tile-variants" role="tablist" aria-label={`${tile.title} variants`}>
              {tile.variants.map((v) => (
                <button
                  key={v.label}
                  type="button"
                  role="tab"
                  aria-selected={v.label === variant.label}
                  className={`tile-variant${v.label === variant.label ? " active" : ""}`}
                  onClick={() => setVariant(v)}
                >
                  {v.label}
                </button>
              ))}
            </div>
          )}
          <a className="tile-open" href={src} target="_blank" rel="noreferrer">open ↗</a>
        </div>
      </header>
      <div className="tile-frame-wrap">
        <iframe
          key={src}
          className="tile-frame"
          src={src}
          title={tile.title}
          loading="lazy"
        />
      </div>
    </article>
  );
}

function App() {
  const [fullscreen, setFullscreen] = useState(false);

  return (
    <div className={`catalogue${fullscreen ? " catalogue-single" : ""}`}>
      <header className="catalogue-header">
        <div className="catalogue-title-group">
          <h1 className="catalogue-title">Elastic Security · Harness</h1>
          <p className="catalogue-sub">
            Storybook-like preview for the six MCP app views. Edit
            <code> harness/fixtures/&lt;view&gt;.ts</code> and Vite will hot-reload.
            Press <kbd>T</kbd> inside any view to toggle dark/light.
          </p>
        </div>
        <div className="catalogue-tools">
          <button
            type="button"
            className="catalogue-tool"
            onClick={() => setFullscreen((f) => !f)}
          >
            {fullscreen ? "grid layout" : "stacked layout"}
          </button>
          <a className="catalogue-tool" href="https://github.com/elastic/example-mcp-app-security" target="_blank" rel="noreferrer">
            repo ↗
          </a>
        </div>
      </header>
      <main className="catalogue-grid">
        {VIEWS.map((t) => (<ViewTile key={t.slug} tile={t} />))}
      </main>
      <footer className="catalogue-footer">
        Harness is dev-only. Fixtures live in <code>harness/fixtures/</code>.
      </footer>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);

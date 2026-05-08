/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { marked } from "marked";

/**
 * Render a markdown string to HTML, suitable for `dangerouslySetInnerHTML`.
 *
 * Uses GitHub-flavoured markdown with single newlines treated as line breaks
 * (matches how comments and case descriptions are typically authored). Falls
 * back to a `<br>`-joined plain-text rendering if the parser throws.
 */
export function renderMarkdown(text: string): string {
  if (!text) return "";
  try {
    return marked.parse(text, { async: false, gfm: true, breaks: true });
  } catch {
    return escapeHtml(text).replaceAll("\n", "<br>");
  }
}

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

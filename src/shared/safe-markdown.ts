/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import DOMPurify from "dompurify";
import { renderMarkdown } from "./markdown";

/**
 * Render untrusted (e.g. LLM-generated) markdown to sanitized HTML for
 * `dangerouslySetInnerHTML`. Browser-only: DOMPurify needs a DOM, so the
 * server must not import this module.
 */
export function renderSafeMarkdown(text: string | undefined | null): string {
  if (!text) return "";
  return DOMPurify.sanitize(renderMarkdown(text), {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "form", "input", "button", "iframe", "object", "embed"],
    FORBID_ATTR: ["style"],
  });
}

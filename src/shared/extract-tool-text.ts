/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

/**
 * Extract text from a tool result, handling the various shapes
 * that different MCP hosts (Claude Desktop, basic-host, etc.) may send.
 */
export function extractToolText(result: unknown): string | null {
  if (!result || typeof result !== "object") return null;

  const r = result as Record<string, unknown>;

  // Shape 1: { content: [{ type: "text", text: "..." }] }
  if (Array.isArray(r.content)) {
    const textItem = r.content.find(
      (c: unknown) => c && typeof c === "object" && (c as Record<string, unknown>).type === "text"
    ) as { text?: string } | undefined;
    if (textItem?.text) return textItem.text;
  }

  // Shape 2: { result: { content: [...] } }
  if (r.result && typeof r.result === "object") {
    return extractToolText(r.result);
  }

  // Shape 3: { text: "..." } directly
  if (typeof r.text === "string") return r.text;

  // Shape 4: it's a string itself (some hosts send raw text)
  if (typeof result === "string") return result;

  // Shape 5: { type: "text", text: "..." } (single content item, not array)
  if (r.type === "text" && typeof r.text === "string") return r.text;

  return null;
}

/**
 * Extract text from a callServerTool response.
 */
export function extractCallResult(result: unknown): string | null {
  return extractToolText(result);
}

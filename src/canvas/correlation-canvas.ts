/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Paint-by-numbers correlation canvas.
 *
 * Cursor renders MCP app views inline in chat only — it has no side-panel
 * surface for MCP UI resources. Cursor's native "beside the chat" surface is a
 * Canvas: a self-contained .canvas.tsx file (no runtime fetch). So we keep the
 * presentation frozen as a template (correlation-report.canvas.tmpl) and inject
 * a run's render-shape findings as the data — the same `findings` object
 * get_correlation_run hands to render_correlation.
 *
 * This is OPT-IN: it only fires when CORRELATION_CANVAS_DIR is set (point it at
 * the Cursor workspace's canvases dir). Unset → no-op, app behaves unchanged.
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TEMPLATE_NAME = "correlation-report.canvas.tmpl";
const PLACEHOLDER = "__FINDINGS_JSON__";

/** Canvas output dir from env, or undefined when emission is disabled. */
export function canvasDirFromEnv(): string | undefined {
  const dir = process.env.CORRELATION_CANVAS_DIR?.trim();
  return dir ? dir : undefined;
}

/** Locate the canvas template across dev (tsx), tsc, and bundle layouts. */
function resolveTemplatePath(): string {
  const candidates = [
    // co-located when bundled/copied next to this module
    path.resolve(HERE, TEMPLATE_NAME),
    // tsx dev: HERE = src/canvas → repo-root/scripts
    path.resolve(HERE, "../../scripts", TEMPLATE_NAME),
    // tsc: HERE = dist/src/canvas → repo-root/scripts
    path.resolve(HERE, "../../../scripts", TEMPLATE_NAME),
    // esbuild bundle: HERE = dist → repo-root/scripts
    path.resolve(HERE, "../scripts", TEMPLATE_NAME),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return candidates[0];
}

/** Short, stable, kebab slug for the canvas filename. */
function slug(caseTitle: string | undefined, runId: string): string {
  const title = caseTitle?.trim();
  if (title && title.toLowerCase() !== "pasted case") {
    const s = title
      .replace(/[^A-Za-z0-9 ]/g, "")
      .trim()
      .split(/\s+/)
      .slice(0, 5)
      .join("-");
    if (s) return s;
  }
  return runId.slice(0, 8);
}

export interface EmitCanvasParams {
  /** Render-shape findings (from workflowFindingsToRenderShape). */
  findings: Record<string, unknown>;
  runId: string;
  caseTitle?: string;
  /** Output dir; defaults to CORRELATION_CANVAS_DIR. */
  dir?: string;
}

export interface EmitCanvasResult {
  file: string;
}

/**
 * Stamp `findings` into the canvas template and write a self-contained
 * .canvas.tsx. Returns null when no output dir is configured (opt-in). Throws
 * only on real IO/template errors so a misconfiguration is loud.
 */
export function emitCorrelationCanvas(params: EmitCanvasParams): EmitCanvasResult | null {
  const dir = params.dir ?? canvasDirFromEnv();
  if (!dir) return null;

  const templatePath = resolveTemplatePath();
  const template = fs.readFileSync(templatePath, "utf-8");
  if (!template.includes(PLACEHOLDER)) {
    throw new Error(`canvas template ${templatePath} missing ${PLACEHOLDER} placeholder`);
  }

  const canvas = template.replace(PLACEHOLDER, JSON.stringify(params.findings, null, 2));
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `correlation-${slug(params.caseTitle, params.runId)}.canvas.tsx`);
  fs.writeFileSync(file, canvas);
  return { file };
}

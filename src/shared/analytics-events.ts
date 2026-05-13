/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Canonical list of view identifiers reported in the `view_rendered`
 * telemetry event.
 *
 * Shared between the React views (which call `useAnalytics().trackViewRendered`)
 * and the server-side report-analytics-event tool (whose Zod input schema
 * is `z.enum(VIEW_IDS)`). Adding a view means appending a literal here;
 * renaming or removing one is a dashboard-impacting event.
 */
export const VIEW_IDS = [
  "alert-triage",
  "attack-discovery",
  "case-management",
  "detection-rules",
  "sample-data",
  "threat-hunt",
] as const;

export type ViewId = (typeof VIEW_IDS)[number];

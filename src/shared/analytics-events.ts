/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const VIEW_IDS = [
  "alert-triage",
  "attack-discovery",
  "case-management",
  "detection-rules",
  "sample-data",
  "threat-hunt",
  "correlation",
  "correlation-input",
  "correlation-report",
] as const;

export type ViewId = (typeof VIEW_IDS)[number];

export type ViewRenderedEvent = {
  readonly eventType: "view_rendered";
  readonly viewId: ViewId;
};

export type AnalyticsEvent = ViewRenderedEvent;

export const ANALYTICS_EVENT_TYPES = ["view_rendered"] as const;
export type AnalyticsEventType = (typeof ANALYTICS_EVENT_TYPES)[number];

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const RUN_ID_RE = /^[a-z0-9][a-z0-9-]{2,80}$/;
export const TECHNIQUE_ID_RE = /^T\d{4}(?:\.\d{3})?$/;
export const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const COMMIT_RE = /^[0-9a-f]{40}$/i;
export const TARGET_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$/;

export function assertSafeRunId(runId: string): void {
  if (!RUN_ID_RE.test(runId)) {
    throw new Error(`Invalid run_id "${runId}"`);
  }
}

export function assertSafeTargetId(targetId: string): void {
  if (!TARGET_ID_RE.test(targetId)) {
    throw new Error(`Invalid target_id "${targetId}"`);
  }
}

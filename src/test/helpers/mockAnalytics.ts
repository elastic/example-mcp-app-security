/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi } from "vitest";
import type { AnalyticsClient } from "../../elastic/analytics/index.js";

/**
 * No-op {@link AnalyticsClient} for tests and one-off scripts. Every
 * method is a `vi.fn()` so call sites can assert on invocations when
 * needed; methods that return `Promise<void>` resolve immediately.
 */
export function createMockAnalyticsClient(): AnalyticsClient {
  return {
    trackToolCalled: vi.fn(),
    trackViewRendered: vi.fn(),
    setOptIn: vi.fn(),
    setClusterContext: vi.fn(),
    setLicenseContext: vi.fn(),
    shutdown: vi.fn().mockResolvedValue(undefined),
  };
}

/**
 * Lightweight noop variant used in places where call assertions are
 * unnecessary (e.g. wiring smoke tests). Every method is a no-op.
 */
export const noopAnalyticsClient: AnalyticsClient = {
  trackToolCalled: () => {},
  trackViewRendered: () => {},
  setOptIn: () => {},
  setClusterContext: () => {},
  setLicenseContext: () => {},
  shutdown: async () => {},
};

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { Agent } from "node:https";
import type { ClusterCredentials } from "../credential-client/index.js";

/**
 * Build an {@link Agent} for axios `httpsAgent` from cluster TLS settings.
 *
 * Returns `undefined` when both cluster URLs are plain `http://` so dev
 * clusters without TLS don't carry an unused agent.
 */
export function createHttpsAgent(creds: ClusterCredentials): Agent | undefined {
  if (
    !creds.elasticsearchUrl.startsWith("https://") &&
    !creds.kibanaUrl.startsWith("https://")
  ) {
    return undefined;
  }

  return new Agent({
    rejectUnauthorized: creds.sslVerify,
    ca: creds.caCert,
  });
}

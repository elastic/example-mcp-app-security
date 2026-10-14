/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

/**
 * Point `createServer()` at `clustersJson` and return a function that puts
 * the caller's environment back. `CLUSTERS_FILE` is cleared because it takes
 * precedence over `CLUSTERS_JSON`.
 */
export function installClustersJson(clustersJson: string): () => void {
  const originalJson = process.env.CLUSTERS_JSON;
  const originalFile = process.env.CLUSTERS_FILE;

  process.env.CLUSTERS_JSON = clustersJson;
  delete process.env.CLUSTERS_FILE;

  return () => {
    restoreEnv("CLUSTERS_JSON", originalJson);
    restoreEnv("CLUSTERS_FILE", originalFile);
  };
}

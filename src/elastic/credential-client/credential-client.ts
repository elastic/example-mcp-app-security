/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Credentials for a single Elastic Stack cluster (Elasticsearch + Kibana).
 *
 * Sensitive — contains the cluster's API key. Do not log, do not include in
 * tool results that go to the LLM, do not forward to UI views. For an
 * LLM-safe / view-safe representation, use {@link ClusterSummary} instead.
 */
export interface ClusterCredentials {
  readonly name: string;
  readonly elasticsearchUrl: string;
  readonly kibanaUrl: string;
  readonly elasticsearchApiKey: string;
  /** Whether to verify TLS certificates (default `true`). */
  readonly sslVerify: boolean;
  /** Custom CA bundle, pre-loaded at startup when `caCertPath` was set. */
  readonly caCert?: Buffer;
}

/**
 * Non-sensitive summary of a configured cluster. Safe to return from tool
 * results and forward to UI views — never contains secrets.
 */
export interface ClusterSummary {
  readonly name: string;
  readonly isDefault: boolean;
}

/**
 * Provides per-cluster Elastic Stack credentials.
 *
 * Built once at server startup from the `CLUSTERS_FILE` or `CLUSTERS_JSON`
 * environment variables and injected into anything that needs to address a
 * specific cluster (typically via the client factory, not directly).
 */
export interface CredentialClient {
  /**
   * Resolve credentials for a cluster.
   *
   * @param name  Cluster name. Omit to get the default cluster (the first
   *              entry in the configured array).
   * @throws if `name` is provided but no such cluster exists.
   */
  get(name?: string): ClusterCredentials;

  /**
   * Non-sensitive list of every configured cluster, with the default flagged.
   * Safe to send to the LLM and to UI views.
   */
  list(): readonly ClusterSummary[];

  /** Name of the default cluster (first entry in the configured array). */
  defaultName(): string;
}

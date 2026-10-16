/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Error raised for failed Kibana calls; `status` is undefined for network
 * failures. Kept free of the axios import so services can `instanceof`-check
 * it without loading the HTTP stack.
 */
export class KibanaHttpError extends Error {
  readonly status?: number;
  readonly body?: unknown;

  constructor(message: string, status?: number, body?: unknown) {
    super(message);
    this.name = "KibanaHttpError";
    this.status = status;
    this.body = body;
  }
}

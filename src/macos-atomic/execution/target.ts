/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { assertSafeTargetId } from "../shared/validation.js";
import { runProcess, type ProcessResult } from "./process.js";

export async function runOnTarget(
  scope: AtomicPlan["scope"],
  remoteArgs: readonly string[],
  timeoutMs: number,
  options: { readonly input?: string | Buffer } = {}
): Promise<ProcessResult> {
  assertSafeTargetId(scope.target_id);
  if (scope.target_kind === "tart") {
    return runProcess(
      "tart",
      [
        "exec",
        ...(options.input === undefined ? [] : ["-i"]),
        scope.target_id,
        ...remoteArgs,
      ],
      { timeoutMs, input: options.input }
    );
  }
  return runSsh(scope, scope.target_id, remoteArgs, timeoutMs, options.input);
}

async function runSsh(
  scope: AtomicPlan["scope"],
  host: string,
  remoteArgs: readonly string[],
  timeoutMs: number,
  input?: string | Buffer
): Promise<ProcessResult> {
  if (!scope.ssh_identity_file) {
    throw new Error("SSH targets require a digest-approved identity file");
  }
  const remoteCommand = remoteArgs.map(shellQuoteArg).join(" ");
  return runProcess(
    "ssh",
    [
      "-i",
      scope.ssh_identity_file,
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "--",
      sshTargetDestination(scope.execution_user, host),
      remoteCommand,
    ],
    { timeoutMs, input }
  );
}

export function sshTargetDestination(executionUser: string, targetId: string): string {
  return `${executionUser}@${targetId}`;
}

export function shellQuoteArg(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}


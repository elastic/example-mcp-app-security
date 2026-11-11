/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { assertSafeTargetId } from "../shared/validation.js";
import { runProcess, type ProcessResult } from "./process.js";
import { runOnQemuTarget } from "./qemu-freebsd.js";

export async function runOnTarget(
  scope: AtomicPlan["scope"],
  remoteArgs: readonly string[],
  timeoutMs: number,
  options: { readonly input?: string | Buffer } = {}
): Promise<ProcessResult> {
  assertSafeTargetId(scope.target_id);
  switch (scope.target_kind) {
    case "multipass":
      return runProcess(
        "multipass",
        ["exec", scope.target_id, "--", ...remoteArgs],
        { timeoutMs, input: options.input }
      );
    case "docker":
      const dockerInvocation = dockerExecInvocation(remoteArgs);
      return runProcess(
        "docker",
        [
          "exec",
          "-u",
          dockerInvocation.user,
          scope.target_id,
          ...dockerInvocation.args,
        ],
        { timeoutMs, input: options.input }
      );
    case "ssh": {
      // OpenSSH joins the trailing argv with spaces and the remote login shell
      // re-parses the result (unlike `multipass exec <vm> -- ...`, which delivers
      // argv directly with no intermediate shell). Shell-quote each token into one
      // command string so shell-special characters (e.g. the pwsh version probe
      // `$PSVersionTable.PSVersion.ToString()`) reach the remote program intact
      // instead of being re-parsed by the remote bash.
      const remoteCommand = remoteArgs.map(shellQuoteArg).join(" ");
      return runProcess(
        "ssh",
        [
          "-o",
          "BatchMode=yes",
          "-o",
          "StrictHostKeyChecking=no",
          "-o",
          "UserKnownHostsFile=/dev/null",
          "--",
          sshTargetDestination(scope.execution_user, scope.target_id),
          remoteCommand,
        ],
        { timeoutMs, input: options.input }
      );
    }
    case "qemu":
      return runOnQemuTarget(scope.target_id, remoteArgs, timeoutMs, options.input);
  }
}

export function sshTargetDestination(executionUser: string, targetId: string): string {
  return `${executionUser}@${targetId}`;
}

// POSIX-safe single-quote wrapping for a single shell token: wrap in single
// quotes and escape any embedded single quote as '\''. Used only for the ssh
// target, whose remote command is re-parsed by the remote login shell.
export function shellQuoteArg(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function dockerExecInvocation(remoteArgs: readonly string[]): {
  readonly user: string;
  readonly args: readonly string[];
} {
  if (remoteArgs[0] !== "sudo") return { user: "0", args: remoteArgs };
  if (
    remoteArgs[1] === "-u" &&
    remoteArgs[2] &&
    remoteArgs[3] === "--"
  ) {
    return { user: remoteArgs[2], args: remoteArgs.slice(4) };
  }
  return { user: "0", args: remoteArgs.slice(1) };
}

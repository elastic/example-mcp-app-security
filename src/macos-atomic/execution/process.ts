/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { spawn } from "node:child_process";

export type ProcessResult = {
  readonly command: string;
  readonly args: readonly string[];
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly timedOut: boolean;
  readonly stdout: string;
  readonly stderr: string;
  readonly truncated: boolean;
  readonly startedAt: string;
  readonly endedAt: string;
};

export function runProcess(
  command: string,
  args: readonly string[],
  options: {
    readonly timeoutMs: number;
    readonly maxOutputBytes?: number;
    readonly env?: NodeJS.ProcessEnv;
    readonly input?: string | Buffer;
  }
): Promise<ProcessResult> {
  const maxBytes =
    options.maxOutputBytes ??
    Number(process.env.MACOS_ATOMIC_MAX_OUTPUT_BYTES ?? 1_048_576);
  const startedAt = new Date().toISOString();
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      env: options.env ?? process.env,
      stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
      shell: false,
    });
    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;

    const append = (
      current: Buffer<ArrayBufferLike>,
      chunk: Buffer<ArrayBufferLike>
    ): Buffer<ArrayBufferLike> => {
      if (current.length >= maxBytes) {
        truncated = true;
        return current;
      }
      const remaining = maxBytes - current.length;
      if (chunk.length > remaining) truncated = true;
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };

    child.stdout?.on("data", (chunk: Buffer<ArrayBufferLike>) => {
      stdout = append(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer<ArrayBufferLike>) => {
      stderr = append(stderr, chunk);
    });
    if (options.input !== undefined) child.stdin?.end(options.input);
    child.once("error", reject);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      const hardKill = setTimeout(() => child.kill("SIGKILL"), 2_000);
      hardKill.unref();
    }, options.timeoutMs);
    timer.unref();
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        command,
        args: [...args],
        exitCode,
        signal,
        timedOut,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        truncated,
        startedAt,
        endedAt: new Date().toISOString(),
      });
    });
  });
}

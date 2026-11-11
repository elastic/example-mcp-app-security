/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import path from "node:path";
import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { assertSafeRunId } from "../shared/validation.js";
import { runOnTarget } from "./target.js";

export type ApprovedSourceAsset = NonNullable<
  AtomicPlan["tests"][number]["source_assets"]
>[number];

type SourceAssetVerification = ApprovedSourceAsset & {
  readonly ok: boolean;
  readonly actual_sha256?: string;
  readonly actual_size?: number;
  readonly error?: string;
};

export type StagedSourceAsset = SourceAssetVerification & {
  readonly source_path: string;
  readonly staged_path: string;
};

export type StagedSourceAssets = {
  readonly ok: boolean;
  readonly required: boolean;
  readonly staging_root?: string;
  readonly assets: readonly StagedSourceAsset[];
  readonly error?: string;
};

const SOURCE_ROOT = "/opt/atomic-red-team/atomics";
const STAGING_DIRECTORY = "AtomicRedTeamAssets";

const SOURCE_ASSET_PROBE = String.raw`import hashlib, json, os, stat, sys
flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
descriptor = os.open(sys.argv[1], flags)
try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("source asset is not a regular file")
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    print(json.dumps({"sha256": digest.hexdigest(), "size": metadata.st_size}, sort_keys=True))
finally:
    os.close(descriptor)
`;

// The target resolves the execution user's real home. The stager refuses
// symlinks and copies from the same file descriptor it hashes.
export const OPERATOR_ASSET_MANAGER_SOURCE = String.raw`import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import sys

mode, execution_user, run_id = sys.argv[1:4]
if mode not in {"stage", "verify"}:
    raise SystemExit("invalid source-asset operation")
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,80}", run_id):
    raise SystemExit("invalid run id")

account = pwd.getpwnam(execution_user)
home = pathlib.Path(account.pw_dir)
if not home.is_absolute() or home == pathlib.Path("/"):
    raise SystemExit("unsafe execution-user home")

source_root = pathlib.Path("/opt/atomic-red-team/atomics")
staging_root = home / "AtomicRedTeamAssets" / run_id
assets = json.load(sys.stdin)

def checked_relative_path(value):
    candidate = pathlib.PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
        raise RuntimeError("unsafe source asset path: " + value)
    return candidate

def ensure_directory(directory):
    current = home
    relative = directory.relative_to(home)
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            os.chown(current, account.pw_uid, account.pw_gid)
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("staging path contains a symlink or non-directory: " + str(current))

def open_regular(path_value, flags, mode_bits=0o644):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path_value, flags | nofollow | os.O_NONBLOCK, mode_bits)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise RuntimeError("source asset is not a regular file: " + str(path_value))
    return descriptor

def digest_descriptor(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size

results = []
for asset in assets:
    relative = checked_relative_path(asset["path"])
    source = source_root.joinpath(*relative.parts)
    destination = staging_root.joinpath(*relative.parts)
    source_fd = open_regular(source, os.O_RDONLY)
    try:
        source_digest, source_size = digest_descriptor(source_fd)
        if source_digest != asset["sha256"] or source_size != asset["size"]:
            raise RuntimeError("approved source asset changed: " + asset["path"])
        if mode == "stage":
            ensure_directory(destination.parent)
            destination_fd = open_regular(destination, os.O_WRONLY | os.O_CREAT)
            try:
                os.ftruncate(destination_fd, 0)
                os.lseek(source_fd, 0, os.SEEK_SET)
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_fd, view)
                        view = view[written:]
                os.fchmod(destination_fd, 0o644)
                os.fchown(destination_fd, account.pw_uid, account.pw_gid)
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
    finally:
        os.close(source_fd)

    destination_fd = open_regular(destination, os.O_RDONLY)
    try:
        actual_digest, actual_size = digest_descriptor(destination_fd)
    finally:
        os.close(destination_fd)
    ok = actual_digest == asset["sha256"] and actual_size == asset["size"]
    results.append({
        **asset,
        "source_path": str(source),
        "staged_path": str(destination),
        "actual_sha256": actual_digest,
        "actual_size": actual_size,
        "ok": ok,
    })

print(json.dumps({
    "ok": all(item["ok"] for item in results),
    "required": bool(results),
    "staging_root": str(staging_root),
    "assets": results,
}, sort_keys=True))
`;

export async function verifyApprovedSourceAssets(
  scope: AtomicPlan["scope"],
  tests: AtomicPlan["tests"]
): Promise<{
  readonly ok: boolean;
  readonly assets: readonly SourceAssetVerification[];
}> {
  const unique = collectSourceAssets(tests);
  const results: SourceAssetVerification[] = [];
  for (const asset of unique.values()) {
    const targetPath = sourceAssetPath(asset.path);
    const probe = await runOnTarget(
      scope,
      ["sudo", "python3", "-c", SOURCE_ASSET_PROBE, targetPath],
      30_000
    );
    let parsed: { readonly sha256?: unknown; readonly size?: unknown } = {};
    try {
      parsed = JSON.parse(probe.stdout) as typeof parsed;
    } catch {
      // The structured failure is returned below.
    }
    const actualSha256 = typeof parsed.sha256 === "string" ? parsed.sha256 : "";
    const actualSize = typeof parsed.size === "number" ? parsed.size : Number.NaN;
    const ok =
      probe.exitCode === 0 &&
      !probe.timedOut &&
      actualSha256 === asset.sha256 &&
      Number.isSafeInteger(actualSize) &&
      actualSize === asset.size;
    results.push({
      ...asset,
      ok,
      actual_sha256: actualSha256 || undefined,
      actual_size: Number.isSafeInteger(actualSize) ? actualSize : undefined,
      error: ok
        ? undefined
        : probe.stderr.trim() ||
          "Source asset digest or size did not match the approved plan",
    });
  }
  return { ok: results.every((result) => result.ok), assets: results };
}

export async function stageApprovedOperatorSourceAssets(
  scope: AtomicPlan["scope"],
  runId: string,
  tests: AtomicPlan["tests"]
): Promise<StagedSourceAssets> {
  return manageApprovedOperatorSourceAssets("stage", scope, runId, tests);
}

export async function verifyStagedOperatorSourceAssets(
  scope: AtomicPlan["scope"],
  runId: string,
  tests: AtomicPlan["tests"]
): Promise<StagedSourceAssets> {
  return manageApprovedOperatorSourceAssets("verify", scope, runId, tests);
}

async function manageApprovedOperatorSourceAssets(
  mode: "stage" | "verify",
  scope: AtomicPlan["scope"],
  runId: string,
  tests: AtomicPlan["tests"]
): Promise<StagedSourceAssets> {
  assertSafeRunId(runId);
  const assets = [...collectSourceAssets(tests, true).values()];
  if (assets.length === 0) return { ok: true, required: false, assets: [] };

  const result = await runOnTarget(
    scope,
    [
      "sudo",
      "python3",
      "-c",
      OPERATOR_ASSET_MANAGER_SOURCE,
      mode,
      scope.execution_user,
      runId,
    ],
    Math.max(60_000, assets.length * 30_000),
    { input: JSON.stringify(assets) }
  );
  if (result.exitCode !== 0 || result.timedOut) {
    return {
      ok: false,
      required: true,
      assets: [],
      error:
        result.stderr.trim() ||
        result.stdout.trim() ||
        `Could not ${mode} approved operator source assets`,
    };
  }
  try {
    return parseStagedSourceAssets(result.stdout, assets);
  } catch (error) {
    return {
      ok: false,
      required: true,
      assets: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function parseStagedSourceAssets(
  output: string,
  approved: readonly ApprovedSourceAsset[]
): StagedSourceAssets {
  const value = JSON.parse(output) as Record<string, unknown>;
  if (
    typeof value.ok !== "boolean" ||
    value.required !== true ||
    typeof value.staging_root !== "string" ||
    !Array.isArray(value.assets) ||
    value.assets.length !== approved.length
  ) {
    throw new Error("Target returned an invalid staged source-asset result");
  }
  const expected = new Map(approved.map((asset) => [asset.path, asset]));
  const assets = value.assets.map((candidate) => {
    if (!candidate || typeof candidate !== "object") {
      throw new Error("Target returned an invalid staged source asset");
    }
    const item = candidate as Record<string, unknown>;
    const approvedAsset = typeof item.path === "string" ? expected.get(item.path) : undefined;
    if (
      !approvedAsset ||
      item.sha256 !== approvedAsset.sha256 ||
      item.size !== approvedAsset.size ||
      typeof item.ok !== "boolean" ||
      typeof item.actual_sha256 !== "string" ||
      typeof item.actual_size !== "number" ||
      item.source_path !== sourceAssetPath(approvedAsset.path) ||
      typeof item.staged_path !== "string" ||
      !item.staged_path.startsWith(`${value.staging_root}/`)
    ) {
      throw new Error("Staged source asset did not match the digest-approved plan");
    }
    const expectedOk =
      item.actual_sha256 === approvedAsset.sha256 &&
      item.actual_size === approvedAsset.size;
    if (item.ok !== expectedOk) {
      throw new Error("Target returned an inconsistent staged source-asset result");
    }
    return item as unknown as StagedSourceAsset;
  });
  if (value.ok !== assets.every((asset) => asset.ok)) {
    throw new Error("Target returned an inconsistent source-asset summary");
  }
  return {
    ok: value.ok,
    required: true,
    staging_root: value.staging_root,
    assets,
    error: value.ok
      ? undefined
      : "One or more staged source assets changed after provisioning",
  };
}

function collectSourceAssets(
  tests: AtomicPlan["tests"],
  operatorOnly = false
): Map<string, ApprovedSourceAsset> {
  const unique = new Map<string, ApprovedSourceAsset>();
  for (const test of tests) {
    if (operatorOnly && test.execution_mode !== "operator") continue;
    for (const asset of test.source_assets ?? []) {
      assertSafeAssetPath(asset.path);
      const existing = unique.get(asset.path);
      if (
        existing &&
        (existing.sha256 !== asset.sha256 || existing.size !== asset.size)
      ) {
        throw new Error(`Conflicting approved digests for source asset ${asset.path}`);
      }
      unique.set(asset.path, asset);
    }
  }
  return unique;
}

export function sourceAssetPath(assetPath: string): string {
  assertSafeAssetPath(assetPath);
  return path.posix.join(SOURCE_ROOT, assetPath);
}

export function operatorSourceAssetRelativePath(runId: string, assetPath: string): string {
  assertSafeRunId(runId);
  assertSafeAssetPath(assetPath);
  return path.posix.join(STAGING_DIRECTORY, runId, assetPath);
}

export function assertSafeAssetPath(assetPath: string): void {
  const parts = assetPath.split("/");
  if (
    !assetPath ||
    assetPath.startsWith("/") ||
    assetPath.includes("\\") ||
    assetPath.includes("\0") ||
    assetPath.includes("\r") ||
    assetPath.includes("\n") ||
    parts.some((part) => !part || part === "." || part === "..")
  ) {
    throw new Error(`Unsafe Atomic source asset path: ${assetPath}`);
  }
}

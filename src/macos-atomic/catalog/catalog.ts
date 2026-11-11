/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import YAML from "yaml";
import { sha256 } from "../shared/json.js";
import { GUID_RE, TECHNIQUE_ID_RE } from "../shared/validation.js";

type RawAtomic = {
  name?: unknown;
  auto_generated_guid?: unknown;
  description?: unknown;
  supported_platforms?: unknown;
  input_arguments?: unknown;
  dependencies?: unknown;
  dependency_executor_name?: unknown;
  executor?: unknown;
};

type RawTechnique = {
  attack_technique?: unknown;
  display_name?: unknown;
  atomic_tests?: unknown;
};

export type CatalogInput = {
  readonly description: string;
  readonly type: string;
  readonly default: unknown;
};

export type MacosAtomicTest = {
  readonly technique_id: string;
  readonly technique_name: string;
  readonly test_guid: string;
  readonly name: string;
  readonly description: string;
  readonly executor: string;
  readonly elevation_required: boolean;
  readonly supported_platforms: readonly string[];
  readonly inputs: Readonly<Record<string, CatalogInput>>;
  readonly dependency_count: number;
  readonly has_cleanup: boolean;
  readonly manual: boolean;
  readonly shared_target_safe: boolean;
  readonly risk_flags: readonly string[];
  readonly definition_digest: string;
  readonly definition_file: string;
  readonly target_platform: "macos";
  readonly preferred_distro: string;
  readonly preferred_architecture: "arm64" | "x86_64" | "any";
};

export type Catalog = {
  readonly atomics_path: string;
  readonly revision?: string;
  readonly catalog_digest: string;
  readonly tests: readonly MacosAtomicTest[];
  readonly skipped_files: readonly { file: string; reason: string }[];
};

export type CatalogAsset = {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
};

export function listTestAssets(
  catalog: Catalog,
  testGuid: string
): readonly CatalogAsset[] {
  const test = catalog.tests.find((candidate) => candidate.test_guid === testGuid);
  if (!test) throw new Error("macOS atomic test not found");
  const root = path.resolve(catalog.atomics_path);
  const techniqueDirectory = path.resolve(root, path.dirname(test.definition_file));
  assertContained(root, techniqueDirectory);
  const assets: CatalogAsset[] = [];
  const stack = [techniqueDirectory];
  while (stack.length) {
    const current = stack.pop();
    if (!current) break;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!entry.isFile() || /\.ya?ml$/i.test(entry.name)) continue;
      const stat = fs.statSync(full);
      assets.push({
        path: path.relative(root, full).split(path.sep).join("/"),
        sha256: sha256File(full),
        size: stat.size,
      });
    }
  }
  return assets.sort((left, right) => left.path.localeCompare(right.path));
}

export function loadMacosCatalog(atomicsPath: string): Catalog {
  const root = path.resolve(atomicsPath);
  const stat = fs.statSync(root);
  if (!stat.isDirectory()) throw new Error(`${root} is not a directory`);
  const files = listYamlFiles(root);
  const tests: MacosAtomicTest[] = [];
  const skippedFiles: { file: string; reason: string }[] = [];

  for (const file of files) {
    try {
      const parsed = YAML.parse(fs.readFileSync(file, "utf8")) as RawTechnique;
      if (!parsed || !TECHNIQUE_ID_RE.test(String(parsed.attack_technique ?? ""))) {
        continue;
      }
      const techniqueId = String(parsed.attack_technique);
      const techniqueName = String(parsed.display_name ?? techniqueId);
      if (!Array.isArray(parsed.atomic_tests)) continue;
      for (const rawValue of parsed.atomic_tests) {
        const raw = rawValue as RawAtomic;
        const platforms = stringArray(raw.supported_platforms).map((value) =>
          value.toLowerCase()
        );
        if (!platforms.includes("macos")) continue;
        const guid = String(raw.auto_generated_guid ?? "");
        if (!GUID_RE.test(guid)) {
          skippedFiles.push({ file, reason: "macOS test has no valid GUID" });
          continue;
        }
        const executor = objectRecord(raw.executor);
        const executorName = String(executor.name ?? "unknown").toLowerCase();
        const command = String(executor.command ?? executor.steps ?? "");
        const cleanup = String(executor.cleanup_command ?? "");
        const dependencies = Array.isArray(raw.dependencies) ? raw.dependencies : [];
        const inputArguments = objectRecord(raw.input_arguments);
        const inputs: Record<string, CatalogInput> = {};
        for (const [key, value] of Object.entries(inputArguments)) {
          const input = objectRecord(value);
          inputs[key] = {
            description: String(input.description ?? ""),
            type: String(input.type ?? "string"),
            default: input.default,
          };
        }
        const riskFlags = classifyRisk({
          name: String(raw.name ?? guid),
          description: String(raw.description ?? ""),
          executor: executorName,
          command,
          cleanup,
          dependencyText: JSON.stringify(dependencies),
          elevationRequired: Boolean(executor.elevation_required),
        });
        const compatibility = classifyCompatibility({
          name: String(raw.name ?? guid),
          description: String(raw.description ?? ""),
          command,
          dependencyText: JSON.stringify(dependencies),
        });
        const digestMaterial = {
          technique_id: techniqueId,
          test_guid: guid,
          name: String(raw.name ?? guid),
          description: String(raw.description ?? ""),
          platforms,
          inputs: inputArguments,
          dependencies,
          dependency_executor_name: raw.dependency_executor_name,
          executor,
        };
        tests.push({
          technique_id: techniqueId,
          technique_name: techniqueName,
          test_guid: guid,
          name: String(raw.name ?? guid),
          description: String(raw.description ?? ""),
          executor: executorName,
          elevation_required: Boolean(executor.elevation_required),
          supported_platforms: platforms,
          inputs,
          dependency_count: dependencies.length,
          has_cleanup: cleanup.trim().length > 0,
          manual: executorName.includes("manual"),
          shared_target_safe: isSharedTargetSafe(command),
          risk_flags: riskFlags,
          definition_digest: sha256(digestMaterial),
          definition_file: path.relative(root, file),
          target_platform: compatibility.platform,
          preferred_distro: compatibility.distro,
          preferred_architecture: compatibility.architecture,
        });
      }
    } catch (error) {
      skippedFiles.push({
        file,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
  tests.sort((a, b) =>
    `${a.technique_id}:${a.test_guid}`.localeCompare(`${b.technique_id}:${b.test_guid}`)
  );
  const revision = gitRevision(root);
  const catalogDigest = sha256(
    tests.map((test) => [test.test_guid, test.definition_digest])
  );
  return {
    atomics_path: root,
    revision,
    catalog_digest: catalogDigest,
    tests,
    skipped_files: skippedFiles,
  };
}

function classifyCompatibility(input: {
  readonly name: string;
  readonly description: string;
  readonly command: string;
  readonly dependencyText: string;
}): {
  readonly platform: "macos";
  readonly distro: string;
  readonly architecture: "arm64" | "x86_64" | "any";
} {
  const text =
    `${input.name}\n${input.description}\n${input.command}\n${input.dependencyText}`.toLowerCase();
  const architecture =
    /\b(?:x86_64|amd64|intel mac|arch\s+-x86_64|rosetta)\b/.test(text)
      ? "x86_64"
      : /\b(?:arm64|aarch64|apple silicon|arch\s+-arm64)\b/.test(text)
        ? "arm64"
        : "any";
  return { platform: "macos", distro: "macos-15", architecture };
}

function listYamlFiles(root: string): string[] {
  const files: string[] = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    if (!current) break;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) files.push(full);
    }
  }
  return files.sort();
}

function assertContained(root: string, candidate: string): void {
  const relative = path.relative(root, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Atomic support path resolves outside the atomics directory");
  }
}

function sha256File(file: string): string {
  const digest = createHash("sha256");
  const descriptor = fs.openSync(file, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      digest.update(buffer.subarray(0, read));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return digest.digest("hex");
}

function objectRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

function gitRevision(root: string): string | undefined {
  const result = spawnSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
    timeout: 5_000,
  });
  const value = result.status === 0 ? result.stdout.trim() : "";
  return /^[0-9a-f]{40}$/i.test(value) ? value : undefined;
}

function classifyRisk(input: {
  name: string;
  description: string;
  executor: string;
  command: string;
  cleanup: string;
  dependencyText: string;
  elevationRequired: boolean;
}): string[] {
  const text = `${input.name}\n${input.description}\n${input.command}\n${input.cleanup}\n${input.dependencyText}`.toLowerCase();
  const flags = new Set<string>();
  if (input.executor.includes("manual")) flags.add("manual");
  if (input.elevationRequired) flags.add("elevated");
  if (/\b(rm\s+-rf|mkfs\b|wipefs\b|dd\s+if=|userdel\b|shutdown\b|poweroff\b|halt\b)/.test(text)) {
    flags.add("destructive");
  }
  if (/\b(reboot|shutdown|poweroff|systemctl\s+reboot)\b/.test(text)) flags.add("reboot");
  if (/\b(curl|wget|nc\b|ncat\b|ssh\b|scp\b|ftp\b|http:\/\/|https:\/\/)/.test(text)) {
    flags.add("network");
  }
  if (/\b(remote host|target host|target_url|target_ip|victim|c2|callback|listener)\b/.test(text)) {
    flags.add("external_target");
  }
  if (/\b(crontab|launchctl|launchd|launchagents|launchdaemons|authorized_keys|zshrc|bash_profile)\b/.test(text)) {
    flags.add("persistence");
  }
  if (
    /(?:^|[\s;&|])(touch|mkdir|mkfifo|truncate|cp|mv|rm|ln|chmod|chown|dscl|sysadminctl|defaults|plutil|security|brew|installer|mount|umount|kill|pkill|killall)\b/.test(
      text
    ) ||
    /\blaunchctl\s+(bootstrap|bootout|load|unload|enable|disable|kickstart)\b/.test(
      text
    ) ||
    /\b(pfctl|socketfilterfw|sysctl)\b/.test(text) ||
    /(?:^|[\s\d])>{1,2}\s*(?:\/|#\{|[a-z0-9_.~-])/m.test(text)
  ) {
    flags.add("state_change");
  }
  if (/\b(kextload|kmutil|kernel extension|system extension|dtrace|bpftrace|sysctl)\b/.test(text)) flags.add("kernel");
  if (/\b(osascript|open\s+-a|system events|gui|desktop|finder|safari)\b/.test(text)) flags.add("gui");
  if (
    /\b(tccutil|full disk access|privacy & security|accessibility)\b/.test(text) ||
    (/\bosascript\b/.test(text) && /\b(tell application|system events|finder)\b/.test(text))
  ) flags.add("tcc");
  if (/\b(csrutil|system integrity protection|authenticated-root)\b/.test(text)) flags.add("sip");
  if (/\b(ioreg|nvram|firmware|secure enclave|touch id)\b/.test(text)) flags.add("real_hardware");
  if (/\b(terraform|kubectl|kubernetes|docker|podman|containerd)\b/.test(text)) flags.add("special_runtime");
  if (!input.cleanup.trim() && !input.executor.includes("manual")) flags.add("no_cleanup");
  return [...flags].sort();
}

const SHARED_TARGET_READ_ONLY_COMMANDS = new Set([
  "cat",
  "cut",
  "date",
  "df",
  "du",
  "egrep",
  "env",
  "fgrep",
  "file",
  "grep",
  "head",
  "hostname",
  "id",
  "ls",
  "lsof",
  "netstat",
  "printenv",
  "ps",
  "pwd",
  "readlink",
  "realpath",
  "sort",
  "stat",
  "strings",
  "tail",
  "uname",
  "uniq",
  "uptime",
  "wc",
  "whereis",
  "which",
  "whoami",
]);

function isSharedTargetSafe(command: string): boolean {
  const lines = command
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (!lines.length) return false;
  return lines.every((line) => {
    if (/[;&|><`$(){}\\]/.test(line)) return false;
    const executable = path.posix.basename(line.split(/\s+/, 1)[0] ?? "");
    return SHARED_TARGET_READ_ONLY_COMMANDS.has(executable);
  });
}

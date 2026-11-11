/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ProcessResult } from "./process.js";
import { runOnTarget } from "./target.js";
import type { AtomicPlan } from "../tools/atomic-run-state.js";

const ARTIFACT_BASE =
  "https://artifacts.elastic.co/downloads/beats/elastic-agent";

export const ELASTIC_AGENT_INSTALLER = String.raw`import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

cfg = json.load(sys.stdin)
token = cfg["enrollment_token"]

def clean(value):
    return (value or "").replace(token, "[REDACTED]")

def emit(payload, code=0):
    print(json.dumps(payload))
    raise SystemExit(code)

machine = platform.machine().lower()
if machine in ("x86_64", "amd64"):
    arch = "x86_64"
elif machine in ("aarch64", "arm64"):
    arch = "aarch64"
else:
    emit({"ok": False, "error": "unsupported architecture", "machine": machine}, 2)

version = cfg["version"]
filename = f"elastic-agent-{version}-darwin-{arch}.tar.gz"
url = f"${ARTIFACT_BASE}/{filename}"
checksum_url = f"{url}.sha512"
work = tempfile.mkdtemp(prefix="atomic-elastic-agent-")

try:
    archive = os.path.join(work, filename)
    checksum_file = f"{archive}.sha512"
    urllib.request.urlretrieve(url, archive)
    urllib.request.urlretrieve(checksum_url, checksum_file)
    with open(checksum_file, "r", encoding="utf-8") as handle:
        expected = handle.read().strip().split()[0].lower()
    digest = hashlib.sha512()
    with open(archive, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        emit({"ok": False, "error": "artifact SHA-512 mismatch", "artifact_url": url}, 3)

    with tarfile.open(archive, "r:gz") as bundle:
        if hasattr(tarfile, "data_filter"):
            bundle.extractall(work, filter="data")
        else:
            bundle.extractall(work)
    binary = os.path.join(work, filename[:-7], "elastic-agent")
    command = [
        binary,
        "install",
        "--url",
        cfg["fleet_url"],
        "--enrollment-token",
        token,
        "--non-interactive",
    ]
    if cfg.get("ca_sha256"):
        command.extend(["--ca-sha256", cfg["ca_sha256"]])
    if cfg.get("insecure"):
        command.append("--insecure")
    installed = subprocess.run(command, text=True, capture_output=True)
    payload = {
        "ok": installed.returncode == 0,
        "version": version,
        "architecture": arch,
        "artifact_url": url,
        "artifact_sha512": actual,
        "install_exit_code": installed.returncode,
        "install_stdout": clean(installed.stdout),
        "install_stderr": clean(installed.stderr),
    }
    emit(payload, 0 if installed.returncode == 0 else 4)
except SystemExit:
    raise
except Exception as error:
    emit({"ok": False, "error": clean(str(error)), "error_type": type(error).__name__}, 5)
finally:
    shutil.rmtree(work, ignore_errors=True)
`;

export type ElasticAgentPlan = NonNullable<
  AtomicPlan["instrumentation"]
>["elastic_agent"];

export type ElasticEndpointReadiness = {
  readonly ok: boolean;
  readonly agent_healthy: boolean;
  readonly system_extension_active_enabled: boolean;
  readonly endpoint_install_test_passed: boolean;
  readonly system_extension: Pick<
    ProcessResult,
    "exitCode" | "timedOut" | "stdout" | "stderr"
  >;
  readonly endpoint_install_test: Pick<
    ProcessResult,
    "exitCode" | "timedOut" | "stdout" | "stderr"
  >;
};

export function elasticAgentArtifact(version: string, machine: string): {
  architecture: "x86_64" | "arm64";
  filename: string;
  url: string;
  checksumUrl: string;
} {
  const normalized = machine.toLowerCase();
  const architecture = ["x86_64", "amd64"].includes(normalized)
    ? "x86_64"
    : ["aarch64", "arm64"].includes(normalized)
      ? "arm64"
      : undefined;
  if (!architecture) throw new Error(`Unsupported Elastic Agent architecture: ${machine}`);
  const artifactArchitecture = architecture === "arm64" ? "aarch64" : architecture;
  const filename = `elastic-agent-${version}-darwin-${artifactArchitecture}.tar.gz`;
  const url = `${ARTIFACT_BASE}/${filename}`;
  return { architecture, filename, url, checksumUrl: `${url}.sha512` };
}

export async function installAndVerifyElasticAgent(
  scope: AtomicPlan["scope"],
  plan: ElasticAgentPlan,
  enrollmentToken: string
): Promise<{
  ok: boolean;
  installation: Record<string, unknown>;
  status: Pick<ProcessResult, "exitCode" | "timedOut" | "stdout" | "stderr">;
  endpoint_readiness?: ElasticEndpointReadiness;
}> {
  const install = await runOnTarget(
    scope,
    ["sudo", "python3", "-c", ELASTIC_AGENT_INSTALLER],
    20 * 60_000,
    {
      input: JSON.stringify({
        version: plan.version,
        fleet_url: plan.fleet_url,
        ca_sha256: plan.ca_sha256,
        insecure: plan.insecure,
        enrollment_token: enrollmentToken,
      }),
    }
  );
  const safeInstall = redactResult(install, enrollmentToken);
  const installation = parseInstallerResult(safeInstall.stdout);
  if (install.exitCode !== 0 || install.timedOut || installation.ok !== true) {
    return {
      ok: false,
      installation: {
        ...installation,
        process_exit_code: safeInstall.exitCode,
        timed_out: safeInstall.timedOut,
        process_stderr: safeInstall.stderr,
      },
      status: { exitCode: null, timedOut: false, stdout: "", stderr: "" },
    };
  }

  const deadline = Date.now() + plan.health_timeout_seconds * 1_000;
  let status = await agentStatus(scope);
  let endpointReadiness = await getElasticEndpointReadiness(scope, status);
  while (!endpointReadiness.ok && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5_000));
    status = await agentStatus(scope);
    endpointReadiness = await getElasticEndpointReadiness(scope, status);
  }
  return {
    ok: endpointReadiness.ok,
    installation,
    status,
    endpoint_readiness: endpointReadiness,
  };
}

export async function getElasticAgentStatus(
  scope: AtomicPlan["scope"]
): Promise<Pick<ProcessResult, "exitCode" | "timedOut" | "stdout" | "stderr">> {
  return agentStatus(scope);
}

export async function getElasticEndpointReadiness(
  scope: AtomicPlan["scope"],
  status?: Pick<ProcessResult, "exitCode" | "timedOut" | "stdout" | "stderr">
): Promise<ElasticEndpointReadiness> {
  const agentStatusResult = status ?? (await agentStatus(scope));
  const [systemExtension, endpointInstallTest] = await Promise.all([
    runOnTarget(scope, ["sudo", "systemextensionsctl", "list"], 30_000),
    runOnTarget(
      scope,
      [
        "sudo",
        "/Library/Elastic/Endpoint/elastic-endpoint",
        "test",
        "install",
      ],
      60_000
    ),
  ]);
  const systemExtensionStatus = pickStatus(systemExtension);
  const endpointInstallTestStatus = pickStatus(endpointInstallTest);
  const agentHealthy = isElasticAgentHealthy(agentStatusResult);
  const systemExtensionActiveEnabled =
    systemExtension.exitCode === 0 &&
    !systemExtension.timedOut &&
    isElasticSystemExtensionActiveAndEnabled(systemExtension.stdout);
  const endpointInstallTestPassed =
    endpointInstallTest.exitCode === 0 &&
    !endpointInstallTest.timedOut &&
    elasticEndpointInstallTestPassed(
      `${endpointInstallTest.stdout}\n${endpointInstallTest.stderr}`
    );
  return {
    ok: agentHealthy && systemExtensionActiveEnabled && endpointInstallTestPassed,
    agent_healthy: agentHealthy,
    system_extension_active_enabled: systemExtensionActiveEnabled,
    endpoint_install_test_passed: endpointInstallTestPassed,
    system_extension: systemExtensionStatus,
    endpoint_install_test: endpointInstallTestStatus,
  };
}

export function isElasticSystemExtensionActiveAndEnabled(output: string): boolean {
  const row = output
    .split(/\r?\n/)
    .find((line) => line.includes("co.elastic.systemextension"));
  if (!row) return false;
  const columns = row.split("\t");
  return columns[0]?.trim() === "*" && columns[1]?.trim() === "*";
}

export function elasticEndpointInstallTestPassed(output: string): boolean {
  return !/(?:enable|grant).*Full Disk Access|Full Disk Access.*(?:required|missing|disabled)|(?:approve|allow).*content filter|Connect Kernel has failed/i.test(
    output
  );
}

function parseInstallerResult(stdout: string): Record<string, unknown> {
  const lines = stdout.trim().split("\n").filter(Boolean);
  const last = lines.at(-1);
  if (!last) return { ok: false, error: "Elastic Agent installer returned no result" };
  try {
    return JSON.parse(last) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "Elastic Agent installer returned invalid JSON" };
  }
}

async function agentStatus(
  scope: AtomicPlan["scope"]
): Promise<Pick<ProcessResult, "exitCode" | "timedOut" | "stdout" | "stderr">> {
  const jsonResult = await runOnTarget(
    scope,
    ["sudo", "elastic-agent", "status", "--output", "json"],
    30_000
  );
  if (parseStatusJson(jsonResult.stdout)) return pickStatus(jsonResult);

  // Older Agents may not implement JSON output. Keep their human-readable
  // status usable without weakening the checks for current Agents.
  const result = await runOnTarget(scope, ["sudo", "elastic-agent", "status"], 30_000);
  return pickStatus(result);
}

function pickStatus(
  result: ProcessResult
): Pick<ProcessResult, "exitCode" | "timedOut" | "stdout" | "stderr"> {
  return {
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

export function isElasticAgentHealthy(
  status: Pick<ProcessResult, "exitCode" | "timedOut" | "stdout">
): boolean {
  if (status.exitCode !== 0 || status.timedOut) return false;

  const json = parseStatusJson(status.stdout);
  if (json) {
    if (!isHealthyState(json.state)) return false;
    const fleetState = getCaseInsensitive(json, "fleetState", "fleet_state");
    return fleetState === undefined || isHealthyState(fleetState);
  }

  if (/^State:\s+HEALTHY\s*$/im.test(status.stdout)) return true;
  if (/elastic-agent\b[^\r\n]*\(HEALTHY\)\s+Running\s*$/im.test(stripAnsi(status.stdout))) {
    return true;
  }

  const lines = status.stdout.split(/\r?\n/).map(stripAnsi);
  const agentLine = lines.findIndex((line) => /\belastic-agent\s*$/i.test(line.trim()));
  if (agentLine < 0) return false;
  const topLevelStatus = lines
    .slice(agentLine + 1, agentLine + 4)
    .find((line) => /status:/i.test(line));
  return /status:\s*\(HEALTHY\)\s+Running\s*$/i.test(topLevelStatus?.trim() ?? "");
}

function parseStatusJson(stdout: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(stdout.trim());
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function isHealthyState(value: unknown): boolean {
  return value === 2 || (typeof value === "string" && value.toUpperCase() === "HEALTHY");
}

function getCaseInsensitive(
  value: Record<string, unknown>,
  ...names: string[]
): unknown {
  const normalizedNames = new Set(names.map(normalizeKey));
  const entry = Object.entries(value).find(([key]) => normalizedNames.has(normalizeKey(key)));
  return entry?.[1];
}

function normalizeKey(value: string): string {
  return value.replaceAll("_", "").toLowerCase();
}

function stripAnsi(value: string): string {
  return value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "");
}

function redactResult(result: ProcessResult, secret: string): ProcessResult {
  if (!secret) return result;
  return {
    ...result,
    args: result.args.map((value) => value.replaceAll(secret, "[REDACTED]")),
    stdout: result.stdout.replaceAll(secret, "[REDACTED]"),
    stderr: result.stderr.replaceAll(secret, "[REDACTED]"),
  };
}

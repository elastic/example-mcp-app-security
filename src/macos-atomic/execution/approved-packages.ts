/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { runOnTarget } from "./target.js";

export type ApprovedPackage = NonNullable<
  AtomicPlan["target_prerequisites"]
>["packages"][number];

type PackageVerification = {
  readonly name: string;
  readonly expected_version?: string;
  readonly installed_version?: string;
  readonly ok: boolean;
  readonly exit_code: number | null;
  readonly timed_out: boolean;
  readonly stderr: string;
};

export async function installApprovedPackages(
  scope: AtomicPlan["scope"],
  packages: readonly ApprovedPackage[]
): Promise<{
  readonly ok: boolean;
  readonly install?: Awaited<ReturnType<typeof runOnTarget>>;
  readonly packages: readonly PackageVerification[];
}> {
  if (packages.length === 0) return { ok: true, packages: [] };
  const install = await runOnTarget(
    scope,
    ["brew", "install", ...packages.map(approvedPackageInstallSpec)],
    20 * 60_000
  );
  if (install.exitCode !== 0 || install.timedOut) {
    return { ok: false, install, packages: [] };
  }

  const verification = await verifyApprovedPackages(scope, packages);
  return { ok: verification.ok, install, packages: verification.packages };
}

export async function verifyApprovedPackages(
  scope: AtomicPlan["scope"],
  packages: readonly ApprovedPackage[]
): Promise<{
  readonly ok: boolean;
  readonly packages: readonly PackageVerification[];
}> {
  const results: PackageVerification[] = [];
  for (const approvedPackage of packages) {
    const result = await runOnTarget(
      scope,
      ["brew", "list", "--versions", approvedPackage.name],
      30_000
    );
    const parsed = parseBrewQuery(result.stdout, approvedPackage.name);
    const ok =
      result.exitCode === 0 &&
      !result.timedOut &&
      parsed?.status === "install ok installed" &&
      (approvedPackage.version === undefined || parsed.version === approvedPackage.version);
    results.push({
      name: approvedPackage.name,
      expected_version: approvedPackage.version,
      installed_version: parsed?.version,
      ok,
      exit_code: result.exitCode,
      timed_out: result.timedOut,
      stderr: result.stderr,
    });
  }
  return { ok: results.every((result) => result.ok), packages: results };
}

export function approvedPackageInstallSpec(approvedPackage: ApprovedPackage): string {
  return approvedPackage.version
    ? `${approvedPackage.name}@${approvedPackage.version}`
    : approvedPackage.name;
}

export function parseBrewQuery(
  output: string,
  expectedName: string
): { readonly status: string; readonly version: string } | undefined {
  const [name, version] = output.trim().split(/\s+/, 2);
  if (name !== expectedName || !version) return undefined;
  return { status: "install ok installed", version };
}

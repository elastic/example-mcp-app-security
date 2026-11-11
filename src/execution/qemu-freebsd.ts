/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { assertSafeTargetId } from "../shared/validation.js";
import { runProcess, type ProcessResult } from "./process.js";

const FREEBSD_RELEASE = "15.1-RELEASE";
const FREEBSD_DISTRO = "freebsd-15.1";
const DOWNLOAD_ROOT = `https://download.freebsd.org/releases/VM-IMAGES/${FREEBSD_RELEASE}`;

export type QemuTargetMetadata = {
  readonly schema_version: 1;
  readonly target_id: string;
  readonly platform: "freebsd";
  readonly distro: typeof FREEBSD_DISTRO;
  readonly pid: number;
  readonly ssh_port: number;
  readonly ssh_user: "atomic";
  readonly identity_file: string;
  readonly work_dir: string;
};

export function qemuTargetsRoot(): string {
  const runRoot = path.resolve(
    process.env.ATOMIC_RUNS_DIR ?? path.join(process.cwd(), "atomic-runs")
  );
  return path.join(runRoot, "_qemu-targets");
}

export function qemuTargetDirectory(targetId: string): string {
  assertSafeTargetId(targetId);
  const root = qemuTargetsRoot();
  const directory = path.resolve(root, targetId);
  const relative = path.relative(root, directory);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("QEMU target directory escapes its private root");
  }
  return directory;
}

export function loadQemuTargetMetadata(targetId: string): QemuTargetMetadata {
  const workDir = qemuTargetDirectory(targetId);
  const file = path.join(workDir, "target.json");
  const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<QemuTargetMetadata>;
  if (
    parsed.schema_version !== 1 ||
    parsed.target_id !== targetId ||
    parsed.platform !== "freebsd" ||
    parsed.distro !== FREEBSD_DISTRO ||
    !Number.isSafeInteger(parsed.pid) ||
    !Number.isSafeInteger(parsed.ssh_port) ||
    parsed.ssh_user !== "atomic" ||
    parsed.work_dir !== workDir ||
    parsed.identity_file !== path.join(workDir, "id_ed25519")
  ) {
    throw new Error(`QEMU metadata for ${targetId} is invalid`);
  }
  return parsed as QemuTargetMetadata;
}

export function qemuSshArgs(
  metadata: QemuTargetMetadata,
  remoteArgs: readonly string[]
): string[] {
  return [
    "-i",
    metadata.identity_file,
    "-p",
    String(metadata.ssh_port),
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "--",
    `${metadata.ssh_user}@127.0.0.1`,
    ...remoteArgs.map(posixShellQuote),
  ];
}

export function posixShellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

export async function runOnQemuTarget(
  targetId: string,
  remoteArgs: readonly string[],
  timeoutMs: number,
  input?: string | Buffer
): Promise<ProcessResult> {
  const metadata = loadQemuTargetMetadata(targetId);
  return runProcess("ssh", qemuSshArgs(metadata, remoteArgs), { timeoutMs, input });
}

export async function provisionFreeBsdQemu(
  plan: AtomicPlan,
  options: { readonly cpus: number; readonly memory: string; readonly disk: string }
): Promise<Record<string, unknown>> {
  if (
    plan.scope.target_kind !== "qemu" ||
    plan.scope.platform !== "freebsd" ||
    plan.scope.lifecycle !== "ephemeral" ||
    plan.scope.distro.toLowerCase() !== FREEBSD_DISTRO
  ) {
    throw new Error(`FreeBSD QEMU provisioning requires qemu/freebsd/${FREEBSD_DISTRO}/ephemeral`);
  }
  const targetId = plan.scope.target_id;
  const workDir = qemuTargetDirectory(targetId);
  if (fs.existsSync(workDir)) {
    throw new Error(`QEMU target ${targetId} already has local state; destroy it before retrying`);
  }
  fs.mkdirSync(workDir, { recursive: true, mode: 0o700 });

  try {
    const image = await ensureFreeBsdImage();
    const identityFile = path.join(workDir, "id_ed25519");
    await mustRun("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", identityFile], 30_000);
    const publicKey = fs.readFileSync(`${identityFile}.pub`, "utf8").trim();
    const seedDir = path.join(workDir, "seed");
    fs.mkdirSync(seedDir, { mode: 0o700 });
    fs.writeFileSync(
      path.join(seedDir, "meta-data"),
      `instance-id: ${targetId}\nlocal-hostname: ${targetId}\n`,
      { mode: 0o600 }
    );
    fs.writeFileSync(path.join(seedDir, "user-data"), cloudInitUserData(publicKey), {
      mode: 0o600,
    });
    const seedImage = path.join(workDir, "seed.iso");
    await mustRun(
      "hdiutil",
      [
        "makehybrid",
        "-quiet",
        "-o",
        seedImage,
        seedDir,
        "-iso",
        "-joliet",
        "-iso-volume-name",
        "cidata",
        "-joliet-volume-name",
        "cidata",
      ],
      60_000
    );
    const overlay = path.join(workDir, "disk.qcow2");
    await mustRun(
      "qemu-img",
      ["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, options.disk],
      60_000
    );
    const sshPort = await reserveTcpPort();
    const pidFile = path.join(workDir, "qemu.pid");
    const consoleLog = path.join(workDir, "console.log");
    const qemu = qemuConfiguration({
      cpus: options.cpus,
      memory: options.memory,
      overlay,
      seedImage,
      sshPort,
      pidFile,
      consoleLog,
    });
    const launch = await mustRun(qemu.command, qemu.args, 60_000);
    const pid = Number(fs.readFileSync(pidFile, "utf8").trim());
    if (!Number.isSafeInteger(pid) || pid < 2) throw new Error("QEMU did not write a valid pidfile");
    const metadata: QemuTargetMetadata = {
      schema_version: 1,
      target_id: targetId,
      platform: "freebsd",
      distro: FREEBSD_DISTRO,
      pid,
      ssh_port: sshPort,
      ssh_user: "atomic",
      identity_file: identityFile,
      work_dir: workDir,
    };
    fs.writeFileSync(path.join(workDir, "target.json"), `${JSON.stringify(metadata, null, 2)}\n`, {
      mode: 0o600,
    });
    const ready = await waitForSsh(metadata, 10 * 60_000);
    const bootstrap = await runOnQemuTarget(
      targetId,
      [
        "sudo",
        "env",
        `ART_REPOSITORY=${plan.source.repository}`,
        `ART_REVISION=${plan.source.revision}`,
        `INVOKE_REPOSITORY=${plan.runner.repository}`,
        `INVOKE_REVISION=${plan.runner.revision}`,
        "/bin/sh",
        "-c",
        FREEBSD_BOOTSTRAP_SCRIPT,
      ],
      30 * 60_000
    );
    if (bootstrap.exitCode !== 0 || bootstrap.timedOut) {
      throw new Error(`FreeBSD bootstrap failed: ${bootstrap.stderr.slice(0, 2_000)}`);
    }
    let graphicalBootstrap: ProcessResult | undefined;
    if (plan.scope.capabilities.includes("gui")) {
      graphicalBootstrap = await runOnQemuTarget(
        targetId,
        ["sudo", "/bin/sh", "-c", FREEBSD_GUI_BOOTSTRAP_SCRIPT],
        20 * 60_000
      );
      if (graphicalBootstrap.exitCode !== 0 || graphicalBootstrap.timedOut) {
        throw new Error(
          `FreeBSD virtual-display bootstrap failed: ${graphicalBootstrap.stderr.slice(0, 2_000)}`
        );
      }
    }
    return {
      ok: true,
      launch,
      ready,
      bootstrap,
      graphical_bootstrap: graphicalBootstrap,
      target: {
        kind: "qemu",
        platform: "freebsd",
        distro: FREEBSD_DISTRO,
        release: FREEBSD_RELEASE,
        ssh_port: sshPort,
      },
    };
  } catch (error) {
    const metadataFile = path.join(workDir, "target.json");
    const retained = fs.existsSync(metadataFile);
    if (!retained && fs.existsSync(workDir)) {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
    throw new Error(
      `FreeBSD QEMU provisioning failed for ${targetId}; ${
        retained
          ? "the launched guest is retained for atomic-target destroy"
          : "no guest was launched and temporary local state was removed"
      }: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

export async function resumeFreeBsdQemuProvisioning(
  plan: AtomicPlan
): Promise<Record<string, unknown>> {
  if (
    plan.scope.target_kind !== "qemu" ||
    plan.scope.platform !== "freebsd" ||
    plan.scope.lifecycle !== "ephemeral" ||
    plan.scope.distro.toLowerCase() !== FREEBSD_DISTRO
  ) {
    throw new Error(`FreeBSD QEMU provisioning requires qemu/freebsd/${FREEBSD_DISTRO}/ephemeral`);
  }
  const metadata = loadQemuTargetMetadata(plan.scope.target_id);
  if (!processExists(metadata.pid)) {
    throw new Error(
      `QEMU target ${plan.scope.target_id} has retained local state but its process is not running; destroy it before retrying`
    );
  }
  const ready = await waitForSsh(metadata, 10 * 60_000);
  const bootstrap = await runOnQemuTarget(
    plan.scope.target_id,
    [
      "sudo",
      "env",
      `ART_REPOSITORY=${plan.source.repository}`,
      `ART_REVISION=${plan.source.revision}`,
      `INVOKE_REPOSITORY=${plan.runner.repository}`,
      `INVOKE_REVISION=${plan.runner.revision}`,
      "/bin/sh",
      "-c",
      FREEBSD_BOOTSTRAP_SCRIPT,
    ],
    30 * 60_000
  );
  if (bootstrap.exitCode !== 0 || bootstrap.timedOut) {
    throw new Error(`FreeBSD bootstrap failed: ${bootstrap.stderr.slice(0, 2_000)}`);
  }
  let graphicalBootstrap: ProcessResult | undefined;
  if (plan.scope.capabilities.includes("gui")) {
    graphicalBootstrap = await runOnQemuTarget(
      plan.scope.target_id,
      ["sudo", "/bin/sh", "-c", FREEBSD_GUI_BOOTSTRAP_SCRIPT],
      20 * 60_000
    );
    if (graphicalBootstrap.exitCode !== 0 || graphicalBootstrap.timedOut) {
      throw new Error(
        `FreeBSD virtual-display bootstrap failed: ${graphicalBootstrap.stderr.slice(0, 2_000)}`
      );
    }
  }
  return {
    ok: true,
    resumed: true,
    ready,
    bootstrap,
    graphical_bootstrap: graphicalBootstrap,
    target: {
      kind: "qemu",
      platform: "freebsd",
      distro: FREEBSD_DISTRO,
      release: FREEBSD_RELEASE,
      ssh_port: metadata.ssh_port,
    },
  };
}

export async function destroyFreeBsdQemu(targetId: string): Promise<Record<string, unknown>> {
  const metadata = loadQemuTargetMetadata(targetId);
  let graceful = true;
  try {
    process.kill(metadata.pid, "SIGTERM");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ESRCH") throw error;
  }
  const deadline = Date.now() + 20_000;
  while (processExists(metadata.pid) && Date.now() < deadline) await delay(500);
  if (processExists(metadata.pid)) {
    graceful = false;
    process.kill(metadata.pid, "SIGKILL");
  }
  const workDir = qemuTargetDirectory(targetId);
  fs.rmSync(workDir, { recursive: true, force: false });
  return { ok: true, target_id: targetId, graceful, removed: workDir };
}

export function isQemuTargetRunning(targetId: string): boolean {
  return processExists(loadQemuTargetMetadata(targetId).pid);
}

function cloudInitUserData(publicKey: string): string {
  if (!/^ssh-ed25519 [A-Za-z0-9+/=]+(?:\s|$)/.test(publicKey)) {
    throw new Error("Generated SSH public key has an unexpected format");
  }
  return `#cloud-config
users:
  - default
  - name: atomic
    gecos: Atomic Red Team
    groups: [wheel]
    shell: /bin/sh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ${publicKey}
ssh_pwauth: false
disable_root: true
packages:
  - sudo
`;
}

const FREEBSD_BOOTSTRAP_SCRIPT = String.raw`set -eu
env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
pkg install -y ca_root_nss curl git sudo bash python3 binutils
pyyaml_package="$(pkg search -q pyyaml | grep -E '^py[0-9]+-pyyaml-' | head -n 1)"
test -n "$pyyaml_package"
pkg install -y "$pyyaml_package"
ln -sf "$(command -v python3)" /usr/bin/python3
install_pinned_repo() {
  destination="$1"
  repository="$2"
  revision="$3"
  rm -rf "$destination"
  mkdir -p "$destination"
  git -C "$destination" init
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --depth 1 origin "$revision"
  git -C "$destination" checkout --detach FETCH_HEAD
}
install_pinned_repo /opt/atomic-red-team "$ART_REPOSITORY" "$ART_REVISION"
install_pinned_repo /opt/invoke-atomicredteam "$INVOKE_REPOSITORY" "$INVOKE_REVISION"
install -d -m 1777 /var/tmp/atomic-runs
mkdir -p /proc
mount | grep -q ' on /proc ' || mount -t procfs proc /proc
`;

const FREEBSD_GUI_BOOTSTRAP_SCRIPT = String.raw`set -eu
pkg install -y xorg-vfbserver
if ! pgrep -f '[X]vfb :99' >/dev/null 2>&1; then
  /usr/local/bin/Xvfb :99 -screen 0 1280x800x24 >/var/log/atomic-xvfb.log 2>&1 &
fi
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  test -S /tmp/.X11-unix/X99 && exit 0
  sleep 1
done
exit 1
`;

async function ensureFreeBsdImage(): Promise<string> {
  const architecture = freeBsdArchitecture();
  const fileName = `FreeBSD-${FREEBSD_RELEASE}-${architecture.releaseName}-BASIC-CLOUDINIT-ufs.qcow2.xz`;
  const releaseUrl = `${DOWNLOAD_ROOT}/${architecture.directory}/Latest`;
  const cacheDir = path.resolve(
    process.env.ATOMIC_CACHE_DIR ?? path.join(process.cwd(), ".atomic-cache"),
    "freebsd",
    FREEBSD_RELEASE,
    architecture.directory
  );
  fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  const checksums = path.join(cacheDir, "CHECKSUM.SHA256");
  await download(`${releaseUrl}/CHECKSUM.SHA256`, checksums);
  const expected = parseFreeBsdChecksum(fs.readFileSync(checksums, "utf8"), fileName);
  const archive = path.join(cacheDir, fileName);
  if (!fs.existsSync(archive) || sha256File(archive) !== expected) {
    await download(`${releaseUrl}/${fileName}`, archive);
  }
  if (sha256File(archive) !== expected) throw new Error("FreeBSD image archive checksum mismatch");
  const image = archive.slice(0, -3);
  const imageDigestFile = `${image}.sha256`;
  const validImage =
    fs.existsSync(image) &&
    fs.existsSync(imageDigestFile) &&
    fs.readFileSync(imageDigestFile, "utf8").trim() === sha256File(image);
  if (!validImage) {
    const decompression = await runProcess("xz", ["-d", "-k", "-f", archive], {
      timeoutMs: 20 * 60_000,
    });
    if (decompression.exitCode !== 0 || decompression.timedOut) {
      throw new Error(`Could not decompress FreeBSD image: ${decompression.stderr}`);
    }
    fs.writeFileSync(imageDigestFile, `${sha256File(image)}\n`, { mode: 0o600 });
  }
  return image;
}

function freeBsdArchitecture(): { readonly directory: string; readonly releaseName: string } {
  if (process.arch === "arm64") return { directory: "aarch64", releaseName: "arm64-aarch64" };
  if (process.arch === "x64") return { directory: "amd64", releaseName: "amd64" };
  throw new Error(`FreeBSD QEMU adapter does not support host architecture ${process.arch}`);
}

export function parseFreeBsdChecksum(contents: string, fileName: string): string {
  const escaped = fileName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = contents.match(new RegExp(`^SHA256 \\(${escaped}\\) = ([0-9a-f]{64})$`, "mi"));
  if (!match?.[1]) throw new Error(`Official checksum does not contain ${fileName}`);
  return match[1].toLowerCase();
}

async function download(url: string, destination: string): Promise<void> {
  const temporary = `${destination}.${process.pid}.tmp`;
  const result = await runProcess("curl", ["-fL", "--retry", "3", "-o", temporary, url], {
    timeoutMs: 20 * 60_000,
  });
  if (result.exitCode !== 0 || result.timedOut) {
    if (fs.existsSync(temporary)) fs.rmSync(temporary);
    throw new Error(`Download failed for ${url}: ${result.stderr}`);
  }
  fs.renameSync(temporary, destination);
}

function qemuConfiguration(input: {
  readonly cpus: number;
  readonly memory: string;
  readonly overlay: string;
  readonly seedImage: string;
  readonly sshPort: number;
  readonly pidFile: string;
  readonly consoleLog: string;
}): { readonly command: string; readonly args: readonly string[] } {
  const common = [
    "-smp",
    String(input.cpus),
    "-m",
    qemuMemory(input.memory),
    "-drive",
    `if=virtio,format=qcow2,file=${input.overlay}`,
    "-drive",
    `if=virtio,format=raw,readonly=on,file=${input.seedImage}`,
    "-netdev",
    `user,id=net0,hostfwd=tcp:127.0.0.1:${input.sshPort}-:22`,
    "-device",
    "virtio-net-pci,netdev=net0",
    "-display",
    "none",
    "-serial",
    `file:${input.consoleLog}`,
    "-monitor",
    "none",
    "-daemonize",
    "-pidfile",
    input.pidFile,
  ];
  if (process.arch === "arm64") {
    const firmware = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd";
    if (!fs.existsSync(firmware)) throw new Error(`QEMU firmware is missing: ${firmware}`);
    return {
      command: "qemu-system-aarch64",
      args: [
        "-machine",
        "virt,accel=hvf",
        "-cpu",
        "host",
        "-drive",
        `if=pflash,format=raw,readonly=on,file=${firmware}`,
        ...common,
      ],
    };
  }
  return {
    command: "qemu-system-x86_64",
    args: ["-machine", "q35,accel=hvf", "-cpu", "host", ...common],
  };
}

function qemuMemory(value: string): string {
  const match = /^(\d+)(M|G)$/i.exec(value);
  if (!match) throw new Error("QEMU memory must use M or G units");
  return match[2]!.toUpperCase() === "G"
    ? String(Number(match[1]) * 1024)
    : match[1]!;
}

async function waitForSsh(
  metadata: QemuTargetMetadata,
  timeoutMs: number
): Promise<ProcessResult> {
  const deadline = Date.now() + timeoutMs;
  let last: ProcessResult | undefined;
  while (Date.now() < deadline) {
    last = await runProcess(
      "ssh",
      qemuSshArgs(metadata, ["sudo", "true"]),
      { timeoutMs: 10_000 }
    );
    if (last.exitCode === 0 && !last.timedOut) return last;
    await delay(3_000);
  }
  throw new Error(`Timed out waiting for FreeBSD SSH: ${last?.stderr ?? "no response"}`);
}

async function reserveTcpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Could not allocate a QEMU SSH port"));
        return;
      }
      const port = address.port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function mustRun(
  command: string,
  args: readonly string[],
  timeoutMs: number
): Promise<ProcessResult> {
  const result = await runProcess(command, args, { timeoutMs });
  if (result.exitCode !== 0 || result.timedOut) {
    throw new Error(`${command} failed: ${result.stderr.slice(0, 2_000)}`);
  }
  return result;
}

function sha256File(file: string): string {
  const digest = createHash("sha256");
  const descriptor = fs.openSync(file, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (!read) break;
      digest.update(buffer.subarray(0, read));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return digest.digest("hex");
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

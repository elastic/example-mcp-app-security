/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  parseFreeBsdChecksum,
  posixShellQuote,
  qemuSshArgs,
  type QemuTargetMetadata,
} from "./qemu-freebsd.js";

describe("FreeBSD QEMU adapter helpers", () => {
  it("selects the exact official image checksum", () => {
    const file = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz";
    expect(
      parseFreeBsdChecksum(
        `SHA256 (${file}) = ${"a".repeat(64)}\nSHA256 (other.qcow2.xz) = ${"b".repeat(64)}\n`,
        file
      )
    ).toBe("a".repeat(64));
  });

  it("builds an isolated localhost SSH invocation", () => {
    const metadata: QemuTargetMetadata = {
      schema_version: 1,
      target_id: "freebsd-atomic-a1",
      platform: "freebsd",
      distro: "freebsd-15.1",
      pid: 123,
      ssh_port: 22022,
      ssh_user: "atomic",
      identity_file: "/tmp/freebsd-atomic-a1/id_ed25519",
      work_dir: "/tmp/freebsd-atomic-a1",
    };
    expect(qemuSshArgs(metadata, ["uname", "-a"])).toEqual([
      "-i",
      metadata.identity_file,
      "-p",
      "22022",
      "-o",
      "BatchMode=yes",
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "--",
      "atomic@127.0.0.1",
      "'uname'",
      "'-a'",
    ]);
  });

  it("preserves multiline and quoted remote arguments across OpenSSH", () => {
    expect(posixShellQuote("printf '%s\\n' hello\nwhoami")).toBe(
      "'printf '\"'\"'%s\\n'\"'\"' hello\nwhoami'"
    );
  });
});

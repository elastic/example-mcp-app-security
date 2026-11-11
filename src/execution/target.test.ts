/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import { dockerExecInvocation, sshTargetDestination } from "./target.js";

describe("SSH target identity", () => {
  it("binds the approved execution user into the destination", () => {
    expect(sshTargetDestination("ubuntu", "198.51.100.10")).toBe(
      "ubuntu@198.51.100.10"
    );
  });
});

describe("Docker target privilege mapping", () => {
  it("maps sudo commands to the container root user without requiring sudo", () => {
    expect(dockerExecInvocation(["sudo", "id", "-u"])).toEqual({
      user: "0",
      args: ["id", "-u"],
    });
  });

  it("maps approved non-elevated commands to the approved container user", () => {
    expect(
      dockerExecInvocation(["sudo", "-u", "atomic", "--", "env", "id"])
    ).toEqual({
      user: "atomic",
      args: ["env", "id"],
    });
  });
});

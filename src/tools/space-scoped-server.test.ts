/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createSpaceScopedServer } from "./space-scoped-server.js";
import { currentSpaceId } from "../elastic/shared/space-context.js";
import {
  COUNT_BY_SPACE_TOOL,
  LIST_SPACES_TOOL,
  SPACE_ARG,
} from "../shared/spaces.js";
import {
  createMockMcpServer,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";

const CONFIGURED = "ops";
const EXTRA = { signal: new AbortController().signal };

type Callback = (...args: unknown[]) => unknown;

function setup(): { inner: MockMcpServer; scoped: McpServer } {
  const inner = createMockMcpServer();
  const scoped = createSpaceScopedServer(inner as unknown as McpServer, CONFIGURED);
  return { inner, scoped };
}

/** Register a tool through the scoped server and return what reached the inner server. */
function register(
  scoped: McpServer,
  inner: MockMcpServer,
  name: string,
  inputSchema: unknown,
  handler: Callback
): { inputSchema: unknown; callback: Callback } {
  (scoped.registerTool as unknown as (n: string, c: object, cb: Callback) => void)(
    name,
    { description: "probe", inputSchema },
    handler
  );
  const tool = inner.tool(name);
  return {
    inputSchema: tool.config.inputSchema,
    callback: tool.callback as unknown as Callback,
  };
}

function spaceSchemaOf(inputSchema: unknown): z.ZodType {
  return (inputSchema as Record<string, z.ZodType>)[SPACE_ARG];
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

describe("createSpaceScopedServer", () => {
  describe("input schema", () => {
    it("adds an optional, pattern-checked `space` argument to raw-shape schemas", () => {
      const { inner, scoped } = setup();
      const value = z.string();
      const { inputSchema } = register(scoped, inner, "probe", { value }, vi.fn());

      expect(Object.keys(inputSchema as object).sort()).toEqual([SPACE_ARG, "value"]);
      expect((inputSchema as Record<string, unknown>).value).toBe(value);

      const space = spaceSchemaOf(inputSchema);
      expect(space.safeParse(undefined).success).toBe(true);
      expect(space.safeParse("soc").success).toBe(true);
      expect(space.safeParse("team_a-1").success).toBe(true);
      expect(space.safeParse("Bad Space").success).toBe(false);
      expect(space.safeParse("*").success).toBe(false);
      expect(space.safeParse("").success).toBe(false);
      expect(space.description).toContain(LIST_SPACES_TOOL);
    });

    it("adds `space` to tools that take no arguments (`{}`)", () => {
      const { inner, scoped } = setup();
      const { inputSchema } = register(scoped, inner, "probe", {}, vi.fn());
      expect(Object.keys(inputSchema as object)).toEqual([SPACE_ARG]);
    });

    it("does not mutate the caller's shape object", () => {
      const { inner, scoped } = setup();
      const shape = { value: z.string() };
      register(scoped, inner, "probe", shape, vi.fn());
      expect(Object.keys(shape)).toEqual(["value"]);
    });

    it("passes non-raw-shape schemas through untouched", () => {
      const { inner, scoped } = setup();
      const schema = z.discriminatedUnion("type", [
        z.object({ type: z.literal("a") }),
        z.object({ type: z.literal("b") }),
      ]);
      const objectSchema = z.object({ value: z.string() });

      expect(register(scoped, inner, "union", schema, vi.fn()).inputSchema).toBe(schema);
      expect(register(scoped, inner, "object", objectSchema, vi.fn()).inputSchema).toBe(
        objectSchema
      );
    });

    it.each([LIST_SPACES_TOOL, COUNT_BY_SPACE_TOOL])(
      "does not add `space` to the cross-space tool %s",
      (name) => {
        const { inner, scoped } = setup();
        const shape = { kind: z.enum(["alerts", "discoveries"]) };
        expect(register(scoped, inner, name, shape, vi.fn()).inputSchema).toBe(shape);
      }
    );

    it("refuses a tool that already defines its own `space` argument", () => {
      const { inner, scoped } = setup();
      expect(() =>
        register(scoped, inner, "probe", { [SPACE_ARG]: z.string() }, vi.fn())
      ).toThrow(/already defines a "space" argument/);
    });
  });

  describe("handler", () => {
    it("strips `space` from the args and forwards the rest plus `extra`", async () => {
      const { inner, scoped } = setup();
      const handler = vi.fn(async () => "ok");
      const { callback } = register(scoped, inner, "probe", { value: z.string() }, handler);

      await expect(callback({ value: "x", [SPACE_ARG]: "soc" }, EXTRA)).resolves.toBe("ok");
      expect(handler).toHaveBeenCalledExactlyOnceWith({ value: "x" }, EXTRA);
    });

    it("runs in the configured space when no `space` is passed", async () => {
      const { inner, scoped } = setup();
      const handler = vi.fn(async () => currentSpaceId());
      const { callback } = register(scoped, inner, "probe", {}, handler);

      await expect(callback({}, EXTRA)).resolves.toBe(CONFIGURED);
      expect(handler).toHaveBeenCalledWith({}, EXTRA);
    });

    it("runs in the requested space when `space` is passed", async () => {
      const { inner, scoped } = setup();
      const { callback } = register(scoped, inner, "probe", {}, async () => currentSpaceId());

      await expect(callback({ [SPACE_ARG]: "soc" }, EXTRA)).resolves.toBe("soc");
    });

    it("keeps concurrent calls in different spaces isolated across awaits", async () => {
      const { inner, scoped } = setup();
      const gates = { soc: deferred(), finance: deferred() };
      const { callback } = register(
        scoped,
        inner,
        "probe",
        { gate: z.enum(["soc", "finance"]) },
        async (args) => {
          const before = currentSpaceId();
          await gates[(args as { gate: "soc" | "finance" }).gate].promise;
          await Promise.resolve();
          return { before, after: currentSpaceId() };
        }
      );

      const soc = callback({ gate: "soc", [SPACE_ARG]: "soc" }, EXTRA);
      const finance = callback({ gate: "finance", [SPACE_ARG]: "finance" }, EXTRA);
      const fallback = callback({ gate: "soc" }, EXTRA);

      gates.finance.resolve();
      await expect(finance).resolves.toEqual({ before: "finance", after: "finance" });
      gates.soc.resolve();
      await expect(soc).resolves.toEqual({ before: "soc", after: "soc" });
      await expect(fallback).resolves.toEqual({ before: CONFIGURED, after: CONFIGURED });
      expect(currentSpaceId()).toBe("default");
    });

    it("rejects an invalid `space` that bypassed schema validation", () => {
      const { inner, scoped } = setup();
      const handler = vi.fn();
      const { callback } = register(scoped, inner, "probe", {}, handler);

      expect(() => callback({ [SPACE_ARG]: "*" }, EXTRA)).toThrow(/Invalid Kibana space ID/);
      expect(handler).not.toHaveBeenCalled();
    });

    it.each([LIST_SPACES_TOOL, COUNT_BY_SPACE_TOOL])(
      "runs the cross-space tool %s in the configured space with args untouched",
      async (name) => {
        const { inner, scoped } = setup();
        const handler = vi.fn(async () => currentSpaceId());
        const { callback } = register(scoped, inner, name, {}, handler);

        await expect(callback({ kind: "alerts" }, EXTRA)).resolves.toBe(CONFIGURED);
        expect(handler).toHaveBeenCalledWith({ kind: "alerts" }, EXTRA);
      }
    );

    it("runs non-raw-shape tools in the configured space with args untouched", async () => {
      const { inner, scoped } = setup();
      const handler = vi.fn(async () => currentSpaceId());
      const { callback } = register(
        scoped,
        inner,
        "union",
        z.object({ value: z.string() }),
        handler
      );

      const args = { value: "x", [SPACE_ARG]: "soc" };
      await expect(callback(args, EXTRA)).resolves.toBe(CONFIGURED);
      expect(handler).toHaveBeenCalledWith(args, EXTRA);
    });

    it("forwards `extra` alone for tools without an input schema", async () => {
      const { inner, scoped } = setup();
      const handler = vi.fn(async () => currentSpaceId());
      const { callback } = register(scoped, inner, "bare", undefined, handler);

      await expect(callback(EXTRA)).resolves.toBe(CONFIGURED);
      expect(handler).toHaveBeenCalledExactlyOnceWith(EXTRA);
    });
  });

  it("forwards everything other than registerTool to the wrapped server", () => {
    const { inner, scoped } = setup();
    const readCallback = vi.fn();

    scoped.registerResource("view", "ui://probe/view.html", { mimeType: "text/html" }, readCallback);

    expect(inner.registerResource).toHaveBeenCalledExactlyOnceWith(
      "view",
      "ui://probe/view.html",
      { mimeType: "text/html" },
      readCallback
    );
    expect(inner.resource("ui://probe/view.html").readCallback).toBe(readCallback);
  });
});

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  McpServer,
  RegisteredTool,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runInSpace } from "../elastic/shared/space-context.js";
import {
  COUNT_BY_SPACE_TOOL,
  isValidSpaceId,
  LIST_SPACES_TOOL,
  SPACE_ARG,
  SPACE_ID_PATTERN,
} from "../shared/spaces.js";

/** Tools that span every space, so a per-call `space` makes no sense. */
const CROSS_SPACE_TOOLS: ReadonlySet<string> = new Set([
  LIST_SPACES_TOOL,
  COUNT_BY_SPACE_TOOL,
]);

const spaceArgSchema = z
  .string()
  .regex(SPACE_ID_PATTERN)
  .optional()
  .describe(
    `Kibana space ID to run this call in (e.g. "soc"). Defaults to the configured space; call ${LIST_SPACES_TOOL} to see the available spaces.`,
  );

type OpaqueCb = (...args: unknown[]) => unknown;

interface ToolConfig {
  readonly inputSchema?: unknown;
  readonly [key: string]: unknown;
}

type LooseRegisterTool = (
  name: string,
  config: ToolConfig,
  cb: OpaqueCb,
) => RegisteredTool;

type RawShape = Record<string, z.ZodType>;

function isZodSchema(value: unknown): boolean {
  return typeof value === "object" && value !== null && "_zod" in value;
}

/** A plain `{ arg: z.string() }` shape, as opposed to a zod schema such as `z.object(...)`. */
function isRawShape(schema: unknown): schema is RawShape {
  return (
    typeof schema === "object" &&
    schema !== null &&
    !isZodSchema(schema) &&
    Object.values(schema).every(isZodSchema)
  );
}

function resolveSpace(space: unknown, configuredSpace: string): string {
  if (space === undefined) return configuredSpace;
  if (typeof space !== "string" || !isValidSpaceId(space)) {
    throw new Error(`Invalid Kibana space ID: ${JSON.stringify(space)}`);
  }
  return space;
}

/**
 * Wrap `server` so every tool registered through it runs inside
 * `runInSpace`. Tools with a raw-shape `inputSchema` gain an optional
 * `space` argument, which is stripped before the handler sees its args;
 * everything else runs in `configuredSpace`.
 */
export function createSpaceScopedServer(
  server: McpServer,
  configuredSpace: string,
): McpServer {
  const register = server.registerTool.bind(
    server,
  ) as unknown as LooseRegisterTool;

  const registerTool: LooseRegisterTool = (name, config, cb) => {
    const { inputSchema } = config;

    if (CROSS_SPACE_TOOLS.has(name) || !isRawShape(inputSchema)) {
      return register(name, config, (...args) =>
        runInSpace(configuredSpace, () => cb(...args)),
      );
    }

    if (SPACE_ARG in inputSchema) {
      throw new Error(`Tool "${name}" already defines a "${SPACE_ARG}" argument`);
    }

    return register(
      name,
      { ...config, inputSchema: { ...inputSchema, [SPACE_ARG]: spaceArgSchema } },
      (args, ...rest) => {
        const { [SPACE_ARG]: space, ...toolArgs } = args as Record<string, unknown>;
        return runInSpace(resolveSpace(space, configuredSpace), () =>
          cb(toolArgs, ...rest),
        );
      },
    );
  };

  return new Proxy(server, {
    get(target, prop) {
      if (prop === "registerTool") return registerTool;
      const value: unknown = Reflect.get(target, prop);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import * as monaco from "monaco-editor";
import { loader } from "@monaco-editor/react";
import EditorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker&inline";

/**
 * The view ships as a single inlined HTML bundle (vite-plugin-singlefile) and
 * is served by the MCP server as one HTML resource. Sibling files (workers,
 * JS chunks) are not reachable from the runtime, so:
 *
 *  - `?worker&inline` base64-inlines the editor worker into the bundle so it
 *    doesn't try to fetch a sibling `editor.worker-*.js` at runtime.
 *  - `loader.config({ monaco })` makes `@monaco-editor/react` use the
 *    locally-bundled monaco instead of fetching it from the public CDN.
 *    Without this the editor stays stuck on its "Loading..." placeholder
 *    forever.
 */
(globalThis as unknown as { MonacoEnvironment: { getWorker: (...args: unknown[]) => Worker } }).MonacoEnvironment = {
  getWorker() {
    return new EditorWorker();
  },
};

loader.config({ monaco });

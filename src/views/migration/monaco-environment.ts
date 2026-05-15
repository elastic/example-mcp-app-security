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
 * The view ships as a single inlined HTML bundle (vite-plugin-singlefile).
 * Workers and JS chunks are not reachable at runtime, so:
 *
 *  - `?worker&inline` base64-inlines the editor worker into the bundle.
 *  - `loader.config({ monaco })` makes @monaco-editor/react use the
 *    locally-bundled monaco instead of fetching it from the CDN.
 */
(globalThis as unknown as { MonacoEnvironment: { getWorker: (...args: unknown[]) => Worker } }).MonacoEnvironment = {
  getWorker() {
    return new EditorWorker();
  },
};

loader.config({ monaco });

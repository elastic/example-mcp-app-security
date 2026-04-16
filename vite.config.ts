/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const input = process.env.INPUT;
const viewRoot = input ? path.resolve(__dirname, path.dirname(input)) : __dirname;
const outDir = process.env.VITE_OUT_DIR
  ? path.resolve(__dirname, process.env.VITE_OUT_DIR)
  : path.resolve(__dirname, "dist/views");

export default defineConfig({
  root: viewRoot,
  plugins: [tailwindcss(), react(), viteSingleFile()],
  resolve: {
    alias: {
      "@shared": path.resolve(__dirname, "src/shared"),
    },
  },
  build: {
    outDir,
    emptyOutDir: true,
    rollupOptions: {
      input: input ? path.resolve(__dirname, input) : undefined,
    },
  },
});

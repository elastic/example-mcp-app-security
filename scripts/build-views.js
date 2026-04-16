/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { execSync } from "child_process";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const viewsDir = path.join(root, "src", "views");
const watch = process.argv.includes("--watch");

const views = fs
  .readdirSync(viewsDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

for (const view of views) {
  const input = path.join(viewsDir, view, "mcp-app.html");
  if (!fs.existsSync(input)) continue;

  const outDir = path.join(root, "dist", "views", view);
  const cmd = watch
    ? `npx vite build --watch`
    : `npx vite build`;

  console.log(`Building view: ${view}`);
  execSync(cmd, {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      INPUT: input,
      VITE_OUT_DIR: outDir,
    },
  });
}

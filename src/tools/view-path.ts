import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function resolveViewPath(viewName: string): string {
  const candidates = [
    path.resolve(__dirname, "../../dist/views", viewName, "mcp-app.html"),
    path.resolve(__dirname, "../../../dist/views", viewName, "mcp-app.html"),
    path.resolve(__dirname, "../../views", viewName, "mcp-app.html"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }

  return candidates[0];
}

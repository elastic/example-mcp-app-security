import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

export default defineConfig({
  root: rootDir,
  plugins: [tailwindcss(), react()],
  resolve: {
    alias: {
      // Swap the real ext-apps SDK with our mock
      "@modelcontextprotocol/ext-apps": path.resolve(__dirname, "mock-ext-apps.ts"),
      // Keep the shared alias working
      "@shared": path.resolve(rootDir, "src/shared"),
    },
  },
  server: {
    port: 3456,
    open: "/standalone/harness.html",
  },
});

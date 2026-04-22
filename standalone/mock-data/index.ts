/**
 * Auto-initialize mock data based on the view being loaded.
 *
 * Detects the view name from the URL path (e.g., /src/views/alert-triage/mcp-app.html)
 * and loads the corresponding mock data module.
 */

const path = window.location.pathname;

const viewMatch = path.match(/\/src\/views\/([^/]+)\//);
const viewName = viewMatch?.[1] || new URLSearchParams(window.location.search).get("view") || "";

const loaders: Record<string, () => Promise<{ init: () => void }>> = {
  "alert-triage": () => import("./alert-triage"),
  "attack-discovery": () => import("./attack-discovery"),
  "case-management": () => import("./case-management"),
  "detection-rules": () => import("./detection-rules"),
  "threat-hunt": () => import("./threat-hunt"),
  "sample-data": () => import("./sample-data"),
};

const loader = loaders[viewName];
export const ready: Promise<void> = loader
  ? loader().then((m) => m.init())
  : Promise.resolve(
      console.warn(
        `[mock] Unknown view "${viewName}" — no mock data loaded. Available: ${Object.keys(loaders).join(", ")}`,
      ),
    );

/**
 * Mock implementation of @modelcontextprotocol/ext-apps for standalone dev.
 *
 * Reads `?state=<key>` and `?theme=<light|dark>` from the iframe URL
 * to determine which mock data set to return and which theme to apply.
 */

type ToolResultCallback = (params: unknown) => void;
type HostContextCallback = (params: unknown) => void;
type ToolInputCallback = (params: unknown) => void;
type TeardownCallback = (params: unknown, extra: unknown) => unknown;
type CallToolCallback = (params: unknown, extra: unknown) => Promise<unknown>;
type ListToolsCallback = (params: unknown, extra: unknown) => Promise<unknown>;

interface MockDataRegistry {
  /** Initial tool result sent via ontoolresult after connect */
  toolResult?: unknown;
  /** Map of tool name → mock response for callServerTool */
  toolResponses: Record<string, unknown | ((args: Record<string, unknown>) => unknown)>;
}

// Global registry — populated by mock-data modules
const registry: MockDataRegistry = {
  toolResponses: {},
};

/** Called by mock-data modules to register their fixtures */
export function registerMockData(data: MockDataRegistry) {
  Object.assign(registry, data);
}

/** Get the mock state key from URL params (default: "loaded") */
export function getMockState(): string {
  const params = new URLSearchParams(window.location.search);
  return params.get("state") || "loaded";
}

/** Get the mock theme from URL params (default: "dark") */
export function getMockTheme(): "light" | "dark" {
  const params = new URLSearchParams(window.location.search);
  return (params.get("theme") as "light" | "dark") || "dark";
}

function wrapResponse(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data) }],
  };
}

export class App {
  private _ontoolresult?: ToolResultCallback;
  private _onhostcontextchanged?: HostContextCallback;
  private _ontoolinput?: ToolInputCallback;
  private _ontoolinputpartial?: ToolInputCallback;
  private _ontoolcancelled?: ToolInputCallback;
  private _onteardown?: TeardownCallback;
  private _oncalltool?: CallToolCallback;
  private _onlisttools?: ListToolsCallback;

  constructor(
    public info: { name: string; version: string },
    _capabilities?: unknown,
    _options?: unknown,
  ) {}

  set ontoolresult(cb: ToolResultCallback) {
    this._ontoolresult = cb;
  }
  set onhostcontextchanged(cb: HostContextCallback) {
    this._onhostcontextchanged = cb;
  }
  set ontoolinput(cb: ToolInputCallback) {
    this._ontoolinput = cb;
  }
  set ontoolinputpartial(cb: ToolInputCallback) {
    this._ontoolinputpartial = cb;
  }
  set ontoolcancelled(cb: ToolInputCallback) {
    this._ontoolcancelled = cb;
  }
  set onteardown(cb: TeardownCallback) {
    this._onteardown = cb;
  }
  set oncalltool(cb: CallToolCallback) {
    this._oncalltool = cb;
  }
  set onlisttools(cb: ListToolsCallback) {
    this._onlisttools = cb;
  }

  async connect(_transport?: unknown): Promise<void> {
    // Fire host context (theme) immediately
    const theme = getMockTheme();
    setTimeout(() => {
      this._onhostcontextchanged?.({ hostContext: { theme } });
    }, 0);

    // Fire initial tool result after a short delay (simulates Claude sending params)
    if (registry.toolResult) {
      setTimeout(() => {
        this._ontoolresult?.(wrapResponse(registry.toolResult));
      }, 50);
    }
  }

  async callServerTool(params: {
    name: string;
    arguments?: Record<string, unknown>;
  }): Promise<unknown> {
    const handler = registry.toolResponses[params.name];
    if (!handler) {
      console.warn(`[mock] No mock data for tool: ${params.name}`);
      return wrapResponse({ error: `No mock for ${params.name}` });
    }
    // Simulate network delay
    await new Promise((r) => setTimeout(r, 150));
    const data = typeof handler === "function" ? handler(params.arguments || {}) : handler;
    return wrapResponse(data);
  }

  async requestDisplayMode(params: { mode: string }): Promise<{ mode: string }> {
    // Notify parent harness about display mode change
    window.parent?.postMessage(
      { type: "displayModeChange", mode: params.mode, view: this.info.name },
      "*",
    );
    return { mode: params.mode };
  }

  getHostCapabilities() {
    return { serverTools: true };
  }
  getHostVersion() {
    return { name: "Standalone Harness", version: "1.0.0" };
  }
  getHostContext() {
    return { theme: getMockTheme() };
  }

  async sendMessage() {
    return {};
  }
  async sendLog() {}
  async updateModelContext() {
    return {};
  }
  async openLink(params: { url: string }) {
    window.open(params.url, "_blank");
    return {};
  }
  async downloadFile() {
    return {};
  }
  async requestTeardown() {}
  async sendSizeChanged() {}
  setupSizeChangedNotifications() {
    return () => {};
  }
  close() {}

  // Protocol stubs
  setRequestHandler() {}
  setNotificationHandler() {}
  assertCapabilityForMethod() {}
  assertRequestHandlerCapability() {}
  assertNotificationCapability() {}
}

// Auto-load mock data for the current view
import("./mock-data/index");

// Re-export things views might import from ext-apps
export const RESOURCE_URI_META_KEY = "ui/resourceUri";
export const RESOURCE_MIME_TYPE = "text/html;profile=mcp-app";
export function applyHostStyleVariables() {}
export function applyHostFonts() {}
export function getDocumentTheme() {
  return getMockTheme();
}
export function applyDocumentTheme() {}

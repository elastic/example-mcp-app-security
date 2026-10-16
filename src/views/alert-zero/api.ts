/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useMemo } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { extractCallResult } from "../../shared/extract-tool-text";

/** App-only tool names the view calls (registered in `src/tools/alert-zero.ts`). */
export const ALERT_ZERO_APP_TOOLS = {
  list: "list-alert-zero-proposals",
  detail: "get-alert-zero-proposal-detail",
  investigation: "get-alert-zero-investigation",
  approve: "approve-alert-zero-proposal",
  dismiss: "dismiss-alert-zero-proposal",
} as const;

export interface DownloadableFile {
  readonly filename: string;
  readonly mimeType: string;
  readonly text: string;
}

export interface AlertZeroApi {
  /** Call an app-only tool and JSON-parse its text result. Throws on tool errors. */
  callTool<T>(name: string, args: Record<string, unknown>): Promise<T>;
  /** Open a URL through the host; falls back to `window.open`. */
  openLink(url: string): void;
  /** Post a prompt into the host conversation. */
  sendMessage(text: string): void;
  /** Ask the host to save a file; falls back to a blob link. */
  downloadFile(file: DownloadableFile): void;
}

function fallbackDownload(file: DownloadableFile): void {
  const url = URL.createObjectURL(new Blob([file.text], { type: file.mimeType }));
  const a = document.createElement("a");
  a.href = url;
  a.download = file.filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function createAlertZeroApi(getApp: () => McpApp | null): AlertZeroApi {
  return {
    async callTool<T>(name: string, args: Record<string, unknown>): Promise<T> {
      const app = getApp();
      if (!app) throw new Error("Not connected to the MCP host");
      const result = await app.callServerTool({ name, arguments: args });
      const text = extractCallResult(result);
      if (result.isError) throw new Error(text || `${name} failed`);
      if (!text) throw new Error(`${name} returned no content`);
      return JSON.parse(text) as T;
    },
    openLink(url: string): void {
      const app = getApp();
      if (!app) {
        window.open(url, "_blank", "noopener");
        return;
      }
      void app.openLink({ url }).then(
        (res) => {
          if (res?.isError) window.open(url, "_blank", "noopener");
        },
        () => window.open(url, "_blank", "noopener"),
      );
    },
    sendMessage(text: string): void {
      void getApp()?.sendMessage({ role: "user", content: [{ type: "text", text }] });
    },
    downloadFile(file: DownloadableFile): void {
      const app = getApp();
      if (!app) {
        fallbackDownload(file);
        return;
      }
      void app
        .downloadFile({
          contents: [
            {
              type: "resource",
              resource: { uri: `file:///${file.filename}`, mimeType: file.mimeType, text: file.text },
            },
          ],
        })
        .then(
          (res) => {
            if (res?.isError) fallbackDownload(file);
          },
          () => fallbackDownload(file),
        );
    },
  };
}

export function useAlertZeroApi(getApp: () => McpApp | null): AlertZeroApi {
  return useMemo(() => createAlertZeroApi(getApp), [getApp]);
}

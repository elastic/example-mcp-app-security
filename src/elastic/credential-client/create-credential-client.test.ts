/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCredentialClient } from "./create-credential-client.js";

const ENV_KEYS = ["CLUSTERS_FILE", "CLUSTERS_JSON"] as const;

function setClustersJson(value: object | string): void {
  process.env.CLUSTERS_JSON =
    typeof value === "string" ? value : JSON.stringify(value);
}

const validCluster = (overrides: Partial<{
  name: string;
  elasticsearchUrl: string;
  kibanaUrl: string;
  elasticsearchApiKey: string;
}> = {}) => ({
  name: "primary",
  elasticsearchUrl: "https://es.example.com",
  kibanaUrl: "https://kb.example.com",
  elasticsearchApiKey: "key-1",
  ...overrides,
});

describe("createCredentialClient", () => {
  beforeEach(() => {
    for (const key of ENV_KEYS) {
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of ENV_KEYS) {
      delete process.env[key];
    }
    vi.restoreAllMocks();
  });

  describe("source resolution", () => {
    it("throws when neither CLUSTERS_FILE nor CLUSTERS_JSON is set", () => {
      expect(() => createCredentialClient()).toThrow(
        /No clusters configured/
      );
    });

    it("reads CLUSTERS_FILE when only that variable is set", () => {
      const dir = mkdtempSync(join(tmpdir(), "creds-test-"));
      try {
        const file = join(dir, "clusters.json");
        writeFileSync(file, JSON.stringify([validCluster()]));
        process.env.CLUSTERS_FILE = file;

        const client = createCredentialClient();
        expect(client.defaultName()).toBe("primary");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("prefers CLUSTERS_FILE and emits a console.warn when both are set", () => {
      const dir = mkdtempSync(join(tmpdir(), "creds-test-"));
      try {
        const file = join(dir, "clusters.json");
        writeFileSync(file, JSON.stringify([validCluster({ name: "from-file" })]));
        process.env.CLUSTERS_FILE = file;
        setClustersJson([validCluster({ name: "from-json" })]);

        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

        const client = createCredentialClient();
        expect(client.defaultName()).toBe("from-file");
        expect(warn).toHaveBeenCalledWith(
          expect.stringContaining("preferring CLUSTERS_FILE")
        );
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("wraps a missing CLUSTERS_FILE in a descriptive error", () => {
      process.env.CLUSTERS_FILE = "/path/that/does/not/exist.json";

      expect(() => createCredentialClient()).toThrow(
        /CLUSTERS_FILE: cannot read \/path\/that\/does\/not\/exist\.json/
      );
    });
  });

  describe("schema validation", () => {
    it("throws on malformed JSON, attributing the source", () => {
      process.env.CLUSTERS_JSON = "{not json";
      expect(() => createCredentialClient()).toThrow(
        /CLUSTERS_JSON: invalid JSON/
      );
    });

    it("rejects an empty array", () => {
      setClustersJson([]);
      expect(() => createCredentialClient()).toThrow(
        /at least one cluster is required/
      );
    });

    it("rejects clusters with non-URL values", () => {
      setClustersJson([validCluster({ elasticsearchUrl: "not-a-url" })]);
      expect(() => createCredentialClient()).toThrow(
        /CLUSTERS_JSON: invalid clusters config/
      );
    });

    it("rejects empty cluster names and api keys", () => {
      setClustersJson([validCluster({ name: "" })]);
      expect(() => createCredentialClient()).toThrow(
        /invalid clusters config/
      );
    });

    it("rejects duplicate cluster names", () => {
      setClustersJson([
        validCluster({ name: "dupe" }),
        validCluster({
          name: "dupe",
          elasticsearchApiKey: "key-2",
          elasticsearchUrl: "https://es2.example.com",
          kibanaUrl: "https://kb2.example.com",
        }),
      ]);
      expect(() => createCredentialClient()).toThrow(
        /duplicate cluster name: dupe/
      );
    });
  });

  describe("client behavior", () => {
    it("strips a single trailing slash from URLs and preserves the api key", () => {
      setClustersJson([
        validCluster({
          elasticsearchUrl: "https://es.example.com/",
          kibanaUrl: "https://kb.example.com/",
        }),
      ]);

      const client = createCredentialClient();
      const creds = client.get();

      expect(creds.elasticsearchUrl).toBe("https://es.example.com");
      expect(creds.kibanaUrl).toBe("https://kb.example.com");
      expect(creds.elasticsearchApiKey).toBe("key-1");
    });

    it("returns the default cluster when no name is supplied", () => {
      setClustersJson([
        validCluster({ name: "first" }),
        validCluster({
          name: "second",
          elasticsearchApiKey: "k2",
          elasticsearchUrl: "https://es2.example.com",
          kibanaUrl: "https://kb2.example.com",
        }),
      ]);

      const client = createCredentialClient();

      expect(client.defaultName()).toBe("first");
      expect(client.get().name).toBe("first");
    });

    it("resolves a named cluster", () => {
      setClustersJson([
        validCluster({ name: "first" }),
        validCluster({
          name: "second",
          elasticsearchApiKey: "k2",
          elasticsearchUrl: "https://es2.example.com",
          kibanaUrl: "https://kb2.example.com",
        }),
      ]);

      const client = createCredentialClient();
      expect(client.get("second").elasticsearchApiKey).toBe("k2");
    });

    it("throws when an unknown cluster name is requested", () => {
      setClustersJson([validCluster()]);
      const client = createCredentialClient();

      expect(() => client.get("missing")).toThrow(
        /Cluster "missing" not found\. Available: primary/
      );
    });

    it("list() returns one summary per cluster with the default flagged", () => {
      setClustersJson([
        validCluster({ name: "a" }),
        validCluster({
          name: "b",
          elasticsearchApiKey: "k2",
          elasticsearchUrl: "https://es2.example.com",
          kibanaUrl: "https://kb2.example.com",
        }),
      ]);

      const client = createCredentialClient();
      expect(client.list()).toEqual([
        { name: "a", isDefault: true },
        { name: "b", isDefault: false },
      ]);
    });

    it("returned credentials and summaries are deep-frozen", () => {
      setClustersJson([validCluster()]);

      const client = createCredentialClient();
      const creds = client.get();
      const summary = client.list();

      expect(Object.isFrozen(creds)).toBe(true);
      expect(Object.isFrozen(summary)).toBe(true);
      expect(Object.isFrozen(summary[0])).toBe(true);
    });
  });
});

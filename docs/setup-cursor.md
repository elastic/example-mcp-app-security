# Adding to Cursor

Three options depending on your setup.

## Option 1: Via npx (no local setup required)

Requires Node.js 22+. The server is downloaded and run automatically by Cursor.

Click to install:

<!-- cursor-mcp-config:START -->
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=elastic-security&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsImh0dHBzOi8vZ2l0aHViLmNvbS9lbGFzdGljL2V4YW1wbGUtbWNwLWFwcC1zZWN1cml0eS9yZWxlYXNlcy9sYXRlc3QvZG93bmxvYWQvZWxhc3RpYy1zZWN1cml0eS1tY3AtYXBwLnRneiIsIi0tc3RkaW8iXSwiZW52Ijp7IkNMVVNURVJTX0ZJTEUiOiIiLCJDTFVTVEVSU19KU09OIjoiW3tcIm5hbWVcIjpcInByaW1hcnlcIixcImVsYXN0aWNzZWFyY2hVcmxcIjpcImh0dHBzOi8veW91ci1jbHVzdGVyLmVzLmNsb3VkLmV4YW1wbGUuY29tXCIsXCJraWJhbmFVcmxcIjpcImh0dHBzOi8veW91ci1jbHVzdGVyLmtiLmNsb3VkLmV4YW1wbGUuY29tXCIsXCJlbGFzdGljc2VhcmNoQXBpS2V5XCI6XCJ5b3VyLWFwaS1rZXlcIn1dIn19)
<!-- cursor-mcp-config:END -->

> **Pick one** of `CLUSTERS_JSON` or `CLUSTERS_FILE` — you don't need both. After clicking, Cursor opens its MCP settings with both env vars present:
>
> - **Single cluster (default):** edit `CLUSTERS_JSON` and replace the placeholder URLs and API key. Leave `CLUSTERS_FILE` empty.
> - **Multiple clusters, or to keep secrets out of `mcp.json`:** set `CLUSTERS_FILE` to the absolute path of a JSON file with the same shape and clear `CLUSTERS_JSON`.
>
> See [Creating an API key](./setup-local.md#creating-an-api-key) for how to generate your credentials, and [Cluster configuration](./setup-local.md#cluster-configuration) for the file format.

Or add manually to `.cursor/mcp.json`:

```json
{
  "servers": {
    "elastic-security": {
      "command": "npx",
      "args": [
        "-y",
        "https://github.com/elastic/example-mcp-app-security/releases/latest/download/elastic-security-mcp-app.tgz",
        "--stdio"
      ],
      "env": {
        "CLUSTERS_FILE": "",
        "CLUSTERS_JSON": "[{\"name\":\"primary\",\"elasticsearchUrl\":\"https://your-cluster.es.cloud.example.com\",\"kibanaUrl\":\"https://your-cluster.kb.cloud.example.com\",\"elasticsearchApiKey\":\"your-api-key\"}]"
      }
    }
  }
}
```

> **Pinning a version:** Replace `elastic-security-mcp-app.tgz` with `elastic-security-mcp-app-<version>.tgz` (e.g., `elastic-security-mcp-app-0.2.0.tgz`).

## Option 2: Local server (stdio)

Requires the project to be [built locally](./setup-local.md). Cursor launches the server process directly.

Add to `.cursor/mcp.json`:

```json
{
  "servers": {
    "elastic-security": {
      "command": "node",
      "args": ["/path/to/example-mcp-app-security/dist/main.js", "--stdio"],
      "env": {
        "CLUSTERS_FILE": "",
        "CLUSTERS_JSON": "[{\"name\":\"primary\",\"elasticsearchUrl\":\"https://your-cluster.es.cloud.example.com\",\"kibanaUrl\":\"https://your-cluster.kb.cloud.example.com\",\"elasticsearchApiKey\":\"your-api-key\"}]"
      }
    }
  }
}
```

## Option 3: Local server (HTTP)

Requires the server to be [running locally](./setup-local.md) at `http://localhost:3001/mcp`. Cursor connects over HTTP — the server process runs independently.

Click to install:

<!-- cursor-mcp-config-local:START -->
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=elastic-security&config=eyJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEvbWNwIn0=)
<!-- cursor-mcp-config-local:END -->

Or add manually to `.cursor/mcp.json`:

```json
{
  "servers": {
    "elastic-security": {
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

## Updating

**npx (Option 1):** If your config points to `.../releases/latest/download/elastic-security-mcp-app.tgz`, you're always running the latest version. Just restart the MCP server in Cursor (or restart Cursor) to pick up a new release. If you pinned a specific version, update the version in the tarball filename.

**Build from source (Options 2 & 3):**

```bash
cd example-mcp-app-security
git pull
npm install
npm run build
```

Restart the server (or restart Cursor) after updating.

**Skills:** See [Updating skills](./setup-skills.md#updating-skills).

**Checking your version:** Run the server with `--version`, or check `package.json` in your local clone. For npx, the version is printed in the server startup logs.

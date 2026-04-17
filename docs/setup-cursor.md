# Adding to Cursor

Three options depending on your setup.

## Option 1: Via npx (no local setup required)

Requires Node.js 22+. The server is downloaded and run automatically by Cursor.

Click to install:

<!-- cursor-mcp-config:START -->
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=elastic-security&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsImh0dHBzOi8vZ2l0aHViLmNvbS9lbGFzdGljL3dpcC1leGFtcGxlLW1jcC1hcHAtc2VjdXJpdHkvcmVsZWFzZXMvbGF0ZXN0L2Rvd25sb2FkL2VsYXN0aWMtc2VjdXJpdHktbWNwLWFwcC50Z3oiLCItLXN0ZGlvIl0sImVudiI6eyJFTEFTVElDU0VBUkNIX1VSTCI6Imh0dHBzOi8veW91ci1jbHVzdGVyLmVzLmNsb3VkLmV4YW1wbGUuY29tIiwiRUxBU1RJQ1NFQVJDSF9BUElfS0VZIjoieW91ci1hcGkta2V5IiwiS0lCQU5BX1VSTCI6Imh0dHBzOi8veW91ci1jbHVzdGVyLmtiLmNsb3VkLmV4YW1wbGUuY29tIiwiS0lCQU5BX0FQSV9LRVkiOiJ5b3VyLWtpYmFuYS1hcGkta2V5In19)
<!-- cursor-mcp-config:END -->

> After clicking, replace the placeholder values in Cursor's MCP settings with your actual Elasticsearch and Kibana credentials.

Or add manually to `.vscode/mcp.json`:

```json
{
  "servers": {
    "elastic-security": {
      "command": "npx",
      "args": [
        "-y",
        "https://github.com/elastic/wip-example-mcp-app-security/releases/latest/download/elastic-security-mcp-app.tgz",
        "--stdio"
      ],
      "env": {
        "ELASTICSEARCH_URL": "https://your-cluster.es.cloud.example.com",
        "ELASTICSEARCH_API_KEY": "your-api-key",
        "KIBANA_URL": "https://your-cluster.kb.cloud.example.com",
        "KIBANA_API_KEY": "your-kibana-api-key"
      }
    }
  }
}
```

> **Pinning a version:** Replace `elastic-security-mcp-app.tgz` with `elastic-security-mcp-app-<version>.tgz` (e.g., `elastic-security-mcp-app-0.2.0.tgz`).

## Option 2: Local server (stdio)

Requires the project to be [built locally](./setup-local.md). Cursor launches the server process directly.

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "elastic-security": {
      "command": "node",
      "args": ["/path/to/example-mcp-app-security/dist/main.js", "--stdio"],
      "env": {
        "ELASTICSEARCH_URL": "https://your-cluster.es.cloud.example.com",
        "ELASTICSEARCH_API_KEY": "your-api-key",
        "KIBANA_URL": "https://your-cluster.kb.cloud.example.com",
        "KIBANA_API_KEY": "your-kibana-api-key"
      }
    }
  }
}
```

## Option 3: Local server (HTTP)

Requires the server to be [running locally](./setup-local.md) at `http://localhost:3001/mcp`. Cursor connects over HTTP — the server process runs independently.

Click to install:

<!-- cursor-mcp-config-local:START -->
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=elastic-security-local&config=eyJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjMwMDEvbWNwIn0=)
<!-- cursor-mcp-config-local:END -->

Or add manually to `.vscode/mcp.json`:

```json
{
  "servers": {
    "elastic-security": {
      "url": "http://localhost:3001/mcp"
    }
  }
}
```

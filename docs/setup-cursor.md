# Adding to Cursor

Three options depending on your setup.

## Option 1: Via npx (no local setup required)

Requires Node.js 22+. The server is downloaded and run automatically by Cursor.

Click to install:

<!-- cursor-mcp-config:START -->
[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=elastic-security&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsImh0dHBzOi8vZ2l0aHViLmNvbS9lbGFzdGljL2V4YW1wbGUtbWNwLWFwcC1zZWN1cml0eS9yZWxlYXNlcy9sYXRlc3QvZG93bmxvYWQvZWxhc3RpYy1zZWN1cml0eS1tY3AtYXBwLnRneiIsIi0tc3RkaW8iXSwiZW52Ijp7IkVMQVNUSUNTRUFSQ0hfVVJMIjoiaHR0cHM6Ly95b3VyLWNsdXN0ZXIuZXMuY2xvdWQuZXhhbXBsZS5jb20iLCJFTEFTVElDU0VBUkNIX0FQSV9LRVkiOiJ5b3VyLWFwaS1rZXkiLCJLSUJBTkFfVVJMIjoiaHR0cHM6Ly95b3VyLWNsdXN0ZXIua2IuY2xvdWQuZXhhbXBsZS5jb20iLCJLSUJBTkFfQVBJX0tFWSI6InlvdXIta2liYW5hLWFwaS1rZXkifX0=)
<!-- cursor-mcp-config:END -->

> After clicking, replace the placeholder values in Cursor's MCP settings with your actual Elasticsearch and Kibana credentials.

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

Add to `.cursor/mcp.json`:

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

# Adding to Claude Code

Three options depending on your setup. All use the `claude mcp add` CLI command.

## Option 1: Via npx (no local setup required)

Requires Node.js 22+. The server is downloaded and run automatically by Claude Code.

```bash
claude mcp add elastic-security \
  -e ELASTICSEARCH_URL=https://your-cluster.es.cloud.example.com \
  -e ELASTICSEARCH_API_KEY=your-api-key \
  -e KIBANA_URL=https://your-cluster.kb.cloud.example.com \
  -- npx -y https://github.com/elastic/example-mcp-app-security/releases/latest/download/elastic-security-mcp-app.tgz --stdio
```

> **Pinning a version:** Replace `elastic-security-mcp-app.tgz` with `elastic-security-mcp-app-<version>.tgz` (e.g., `elastic-security-mcp-app-0.2.0.tgz`).
>
> **Required credentials:** Set `ELASTICSEARCH_URL`, `ELASTICSEARCH_API_KEY`, and `KIBANA_URL`. See [Creating an API key](./setup-local.md#creating-an-api-key) for how to generate your credentials.
>
> **Permissions:** For production use, create a scoped role instead of using `superuser`. See [Minimum required permissions](permissions.md) for ready-to-paste role definitions.

## Option 2: Local server (stdio)

Requires the project to be [built locally](./setup-local.md). Claude Code launches the server process directly.

```bash
claude mcp add elastic-security \
  -e ELASTICSEARCH_URL=https://your-cluster.es.cloud.example.com \
  -e ELASTICSEARCH_API_KEY=your-api-key \
  -e KIBANA_URL=https://your-cluster.kb.cloud.example.com \
  -- node /path/to/example-mcp-app-security/dist/main.js --stdio
```

## Option 3: Local server (HTTP)

Requires the server to be [running locally](./setup-local.md) at `http://localhost:3001/mcp`. Claude Code connects over HTTP — the server process runs independently.

```bash
claude mcp add elastic-security \
  --transport http \
  --url http://localhost:3001/mcp
```

## Managing servers

```bash
claude mcp list                       # List registered servers
claude mcp remove elastic-security    # Remove the server
```

> **Scope:** Add `-s user` to register the server globally across all projects, or `-s project` (the default) to scope it to the current project.

# Adding to Claude Code

Three options depending on your setup. All use the `claude mcp add` CLI command.

## Option 1: Via npx (no local setup required)

Requires Node.js 22+. The server is downloaded and run automatically by Claude Code.

```bash
claude mcp add elastic-security \
  -e 'CLUSTERS_JSON=[{"name":"primary","elasticsearchUrl":"https://your-cluster.es.cloud.example.com","kibanaUrl":"https://your-cluster.kb.cloud.example.com","elasticsearchApiKey":"your-api-key"}]' \
  -- npx -y https://github.com/elastic/example-mcp-app-security/releases/latest/download/elastic-security-mcp-app.tgz --stdio
```

> **Pinning a version:** Replace `elastic-security-mcp-app.tgz` with `elastic-security-mcp-app-<version>.tgz` (e.g., `elastic-security-mcp-app-0.2.0.tgz`).
>
> **Keeping secrets out of shell history:** swap `CLUSTERS_JSON` for `CLUSTERS_FILE=/absolute/path/to/clusters.json` pointing at a JSON file with the same array. See [Creating an API key](./setup-local.md#creating-an-api-key) and [Cluster configuration](./setup-local.md#cluster-configuration).

## Option 2: Local server (stdio)

Requires the project to be [built locally](./setup-local.md). Claude Code launches the server process directly.

```bash
claude mcp add elastic-security \
  -e 'CLUSTERS_JSON=[{"name":"primary","elasticsearchUrl":"https://your-cluster.es.cloud.example.com","kibanaUrl":"https://your-cluster.kb.cloud.example.com","elasticsearchApiKey":"your-api-key"}]' \
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

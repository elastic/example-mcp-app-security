# Adding to VS Code

Three options depending on your setup.

## Option 1: Via npx (no local setup required)

Requires Node.js 22+. The server is downloaded and run automatically by VS Code.

Add to `.vscode/mcp.json`:

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

> **Pick one** of `CLUSTERS_JSON` or `CLUSTERS_FILE` — you don't need both.
>
> - **Single cluster (default):** edit `CLUSTERS_JSON` and replace the placeholder URLs and API key. Leave `CLUSTERS_FILE` empty.
> - **Multiple clusters, or to keep secrets out of `mcp.json`:** set `CLUSTERS_FILE` to the absolute path of a JSON file with the same shape and clear `CLUSTERS_JSON`.
>
> **Pinning a version:** Replace `elastic-security-mcp-app.tgz` with `elastic-security-mcp-app-<version>.tgz` (e.g., `elastic-security-mcp-app-0.2.0.tgz`).
>
> See [Creating an API key](./setup-local.md#creating-an-api-key) and [Cluster configuration](./setup-local.md#cluster-configuration) for the details.

## Option 2: Local server (stdio)

Requires the project to be [built locally](./setup-local.md). VS Code launches the server process directly.

Add to `.vscode/mcp.json`:

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

Requires the server to be [running locally](./setup-local.md) at `http://localhost:3001/mcp`. VS Code connects over HTTP — the server process runs independently.

Add to `.vscode/mcp.json`:

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

**npx (Option 1):** If your config points to `.../releases/latest/download/elastic-security-mcp-app.tgz`, you're always running the latest version. Just restart the MCP server in VS Code (or restart VS Code) to pick up a new release. If you pinned a specific version, update the version in the tarball filename.

**Build from source (Options 2 & 3):**

```bash
cd example-mcp-app-security
git pull
npm install
npm run build
```

Restart the server (or restart VS Code) after updating.

**Skills:** See [Updating skills](./setup-skills.md#updating-skills).

**Checking your version:** Run the server with `--version`, or check `package.json` in your local clone. For npx, the version is printed in the server startup logs.

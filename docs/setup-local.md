# Running the Server Locally

Build from source and run the MCP server on your machine.

## Prerequisites

- **Node.js 22+**
- **Elasticsearch 8.x or 9.x** with Security enabled
- **Kibana 8.x or 9.x** (for cases, rules, and attack discovery)
- `CLUSTERS_JSON` (or `CLUSTERS_FILE`) — see [Cluster configuration](#cluster-configuration) below

You need both service URLs plus a single Elasticsearch API key for full functionality.

## Creating an API key

You need an Elasticsearch API key with sufficient privileges for the operations you want to perform (reading alerts, managing cases, writing detection rules, etc.).

- **Kibana UI:** Go to **Stack Management > API Keys > Create API key**
- **Elastic docs:** [Elasticsearch API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys)

For a quick start, a key with the `superuser` role works for all tools. For production, scope the key to the minimum required privileges — see [Minimum required permissions](permissions.md) for ready-to-paste role definitions.

Kibana API keys and Elasticsearch API keys are the same underlying credential type. This project uses the same `elasticsearchApiKey` value for both Elasticsearch and Kibana requests, so you only need to configure one API key.

## Cluster configuration

Set `CLUSTERS_JSON` to a JSON-encoded array with a single cluster:

```json
[
  {
    "name": "primary",
    "elasticsearchUrl": "https://your-cluster.es.cloud.example.com",
    "kibanaUrl": "https://your-cluster.kb.cloud.example.com",
    "elasticsearchApiKey": "your-elasticsearch-api-key",
    "sslVerify": true
  }
]
```

The config is validated at startup — bad JSON, missing fields, or unmodified placeholder URLs/keys fail fast.

### TLS verification options

Self-managed clusters with self-signed or private-CA certificates need extra TLS configuration. Two optional per-cluster fields control this:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `sslVerify` | boolean | `true` | When `false`, skips TLS certificate verification. Use only with trusted self-signed dev clusters. |
| `caCertPath` | string | — | Absolute path to a PEM CA bundle file. Node uses this bundle instead of the system trust store. |

**Precedence:** `sslVerify: false` and `caCertPath` cannot both be set — the server rejects that combination at startup. If you add a CA bundle, make sure `sslVerify` is `true` (or omitted).

**Prefer `caCertPath` over `sslVerify: false`.** Pointing at your private CA keeps verification enabled; disabling verification removes protection against man-in-the-middle attacks.

Example with a custom CA bundle:

```json
[
  {
    "name": "primary",
    "elasticsearchUrl": "https://es.local:9200",
    "kibanaUrl": "https://kb.local:5601",
    "elasticsearchApiKey": "your-api-key",
    "caCertPath": "/absolute/path/to/ca.pem"
  }
]
```

Example for a trusted self-signed dev cluster (insecure — dev only):

```json
[
  {
    "name": "primary",
    "elasticsearchUrl": "https://es.local:9200",
    "kibanaUrl": "https://kb.local:5601",
    "elasticsearchApiKey": "your-api-key",
    "sslVerify": false
  }
]
```

When `sslVerify` is `false`, the server logs a warning at startup. When `caCertPath` is set, it logs an info line confirming the custom CA bundle is in use. Both messages go to stderr (visible in MCP host logs, not in the host UI).

In Claude Desktop's install dialog, the **Verify SSL/TLS Certificates** checkbox maps to `sslVerify`. Uncheck it only for trusted self-signed development clusters.

### Keeping secrets out of config files

If you'd rather not put the API key in `.env` / `mcp.json` directly, set `CLUSTERS_FILE` to the absolute path of a JSON file containing the same array, and leave `CLUSTERS_JSON` unset:

```bash
CLUSTERS_FILE=/absolute/path/to/clusters.json
```

## Steps

```bash
# Clone and install
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install

# Configure
cp .env.example .env
# Edit .env and set CLUSTERS_JSON (or CLUSTERS_FILE) with your cluster details

# Build
npm run build

# Run
npm start
# Server is now running at http://localhost:3001/mcp
```

## Updating

To update a local build to the latest version:

```bash
git pull
npm install
npm run build
```

Then restart the server (`npm start`). Your `.env` configuration is preserved across updates.

**Checking your version:** The current version is in `package.json` (`"version"` field). You can also compare your local HEAD against the [latest release](https://github.com/elastic/example-mcp-app-security/releases/latest).

## Next Steps

With the server running, connect it to your MCP host:

- [Add to Cursor](./setup-cursor.md)
- [Add to Claude Desktop](./setup-claude-desktop.md)
- [Add to Claude.ai](./setup-claude-ai.md)

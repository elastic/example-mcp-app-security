# Running the Server Locally

Build from source and run the MCP server on your machine.

## Prerequisites

- **Node.js 22+**
- **Elasticsearch 8.x or 9.x** with Security enabled
- **Kibana 8.x or 9.x** (for cases, rules, and attack discovery)
- One of `CLUSTERS_JSON` or `CLUSTERS_FILE` (see [Cluster configuration](#cluster-configuration) below)

You need both service URLs plus a single Elasticsearch API key per cluster for full functionality.

## Creating an API key

You need an Elasticsearch API key with sufficient privileges for the operations you want to perform (reading alerts, managing cases, writing detection rules, etc.).

- **Kibana UI:** Go to **Stack Management > API Keys > Create API key**
- **Elastic docs:** [Elasticsearch API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys)

For a quick start, a key with the `superuser` role works for all tools. For production, scope the key to the minimum required privileges.

Kibana API keys and Elasticsearch API keys are the same underlying credential type. This project uses each cluster's `elasticsearchApiKey` for both Elasticsearch and Kibana requests, so you only need to configure one API key value per cluster.

## Cluster configuration

The server reads its cluster list from one of:

- `CLUSTERS_JSON` — a JSON-encoded array passed inline.
- `CLUSTERS_FILE` — the absolute path to a JSON file with the same shape. Wins if both are set.

Each cluster needs a unique `name`. The first entry is used as the default until per-tool cluster selection lands.

### Single cluster

```json
[
  {
    "name": "primary",
    "elasticsearchUrl": "https://your-cluster.es.cloud.example.com",
    "kibanaUrl": "https://your-cluster.kb.cloud.example.com",
    "elasticsearchApiKey": "your-elasticsearch-api-key"
  }
]
```

### Multiple clusters

Same shape, more entries. The first entry (`prod-eu` below) is the default.

```json
[
  {
    "name": "prod-eu",
    "elasticsearchUrl": "https://prod-eu.es.cloud.example.com",
    "kibanaUrl": "https://prod-eu.kb.cloud.example.com",
    "elasticsearchApiKey": "your-prod-eu-api-key"
  },
  {
    "name": "prod-us",
    "elasticsearchUrl": "https://prod-us.es.cloud.example.com",
    "kibanaUrl": "https://prod-us.kb.cloud.example.com",
    "elasticsearchApiKey": "your-prod-us-api-key"
  }
]
```

The config is validated at startup — bad JSON, missing fields, duplicate cluster names, or unmodified placeholder URLs/keys fail fast.

## Steps

```bash
# Clone and install
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install

# Configure
cp .env.example .env
# Edit .env and set CLUSTERS_JSON (or CLUSTERS_FILE) for your cluster(s)

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

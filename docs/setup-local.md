# Running the Server Locally

Build from source and run the MCP server on your machine.

## Prerequisites

- **Node.js 22+**
- **Elasticsearch 8.x or 9.x** with Security enabled
- **Kibana 8.x or 9.x** (for cases, rules, and attack discovery)
- **`ELASTICSEARCH_URL` and `ELASTICSEARCH_API_KEY`**
- **`KIBANA_URL`**

You need both service URLs plus a single Elasticsearch API key for full functionality.

## Creating an API key

You need an Elasticsearch API key with sufficient privileges for the operations you want to perform (reading alerts, managing cases, writing detection rules, etc.).

- **Kibana UI:** Go to **Stack Management > API Keys > Create API key**
- **Elastic docs:** [Elasticsearch API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys)

For a quick start, a key with the `superuser` role works for all tools. For production, scope the key to the minimum required privileges — see [Minimum required permissions](permissions.md) for ready-to-paste role definitions.

Kibana API keys and Elasticsearch API keys are the same underlying credential type. This project uses `ELASTICSEARCH_API_KEY` for both Elasticsearch and Kibana requests, so you only need to configure one API key value.

## Steps

```bash
# Clone and install
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install

# Configure
cp .env.example .env
# Edit .env with your Elasticsearch URL, Kibana URL, and Elasticsearch API key

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

# Running the Server Locally

Build from source and run the MCP server on your machine.

## Prerequisites

- **Node.js 22+**
- **Elasticsearch 8.x or 9.x** with Security enabled
- **Kibana 8.x or 9.x** (for cases, rules, and attack discovery)
- **An Elasticsearch API key** (see [Creating an API key](#creating-an-api-key) below)

## Steps

```bash
# Clone and install
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install

# Configure
cp .env.example .env
# Edit .env with your Elasticsearch/Kibana URLs and API keys

# Build
npm run build

# Run
npm start
# Server is now running at http://localhost:3001/mcp
```

## Creating an API key

You need an Elasticsearch API key with sufficient privileges for the operations you want to perform (reading alerts, managing cases, writing detection rules, etc.).

- **Kibana UI:** Go to **Stack Management > API Keys > Create API key**
- **Elastic docs:** [Elasticsearch API keys](https://www.elastic.co/docs/deploy-manage/api-keys/elasticsearch-api-keys)

For a quick start, a key with the `superuser` role works for all tools. For production, scope the key to the minimum required privileges.

> **Kibana credentials:** `KIBANA_URL` and `KIBANA_API_KEY` are optional — they default to their Elasticsearch counterparts. If you use the same credentials for both, you only need `ELASTICSEARCH_URL` and `ELASTICSEARCH_API_KEY`.

## Next Steps

With the server running, connect it to your MCP host:

- [Add to Cursor](./setup-cursor.md)
- [Add to Claude Desktop](./setup-claude-desktop.md)
- [Add to Claude.ai](./setup-claude-ai.md)

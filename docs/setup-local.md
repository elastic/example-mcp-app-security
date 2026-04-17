# Running the Server Locally

Build from source and run the MCP server on your machine.

## Prerequisites

- **Node.js 22+**
- **Elasticsearch 8.x or 9.x** with Security enabled
- **Kibana 8.x or 9.x** (for cases, rules, and attack discovery)
- **API keys** for both Elasticsearch and Kibana

## Steps

```bash
# Clone and install
git clone https://github.com/elastic/wip-example-mcp-app-security.git
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

## Next Steps

With the server running, connect it to your MCP host:

- [Add to Cursor](./setup-cursor.md)
- [Add to Claude Desktop](./setup-claude-desktop.md)
- [Add to Claude.ai](./setup-claude-ai.md)

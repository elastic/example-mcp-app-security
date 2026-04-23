# Adding to Claude Desktop

## Step 1: Install the MCP App

### Option 1: One-click install (recommended)

Download `example-mcp-app-security.mcpb` from the [latest GitHub release](https://github.com/elastic/example-mcp-app-security/releases/latest) and double-click it.

Claude Desktop opens an install dialog with fields for your Elasticsearch URL, Kibana URL, and Elasticsearch API key:

- `ELASTICSEARCH_URL`
- `ELASTICSEARCH_API_KEY`
- `KIBANA_URL`

> **Permissions:** For production use, create a scoped role instead of using `superuser`. See [Minimum required permissions](permissions.md) for ready-to-paste role definitions.

After install:

- Claude Desktop may show the connector as disabled at first. Toggle it on to enable the server.

### Option 2: Manual config (build from source)

Requires the project to be [built locally](./setup-local.md).

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "elastic-security": {
      "command": "node",
      "args": ["/path/to/example-mcp-app-security/dist/main.js", "--stdio"],
      "env": {
        "ELASTICSEARCH_URL": "https://your-cluster.es.cloud.example.com",
        "ELASTICSEARCH_API_KEY": "your-api-key",
        "KIBANA_URL": "https://your-cluster.kb.cloud.example.com"
      }
    }
  }
}
```

Restart Claude Desktop, then enable the connector if Claude shows it as disabled. The tools appear under the MCP connector menu.

## Step 2: Add Claude Skills

Skills teach Claude _when_ and _how_ to use the tools. Download the skill zips from the [latest GitHub release](https://github.com/elastic/example-mcp-app-security/releases/latest):

- `alert-triage.zip`
- `attack-discovery-triage.zip`
- `case-management.zip`
- `detection-rule-management.zip`
- `generate-sample-data.zip`

In Claude Desktop: **Customize -> Skills -> Create Skill -> Upload a skill**. Upload each zip individually.

If you're building from source, generate the zips locally instead:

```bash
npm run skills:zip
# Produces dist/skills/<skill-name>.zip for each skill
```

# Adding to Claude Desktop

## Option 1: One-click install (recommended)

Download `elastic-security-mcp-app.mcpb` from the [latest GitHub release](https://github.com/elastic/example-mcp-app-security/releases/latest) and double-click it.

Claude Desktop shows an install dialog with a settings UI for your Elasticsearch and Kibana credentials. Sensitive values (API keys) are stored in the OS keychain. No Node.js, cloning, or config-file editing required. See [Creating an API key](./setup-local.md#creating-an-api-key) for how to generate your credentials.

> After installing, the extension appears **disabled** by default. Toggle it to **Enabled** and click **Configure** to enter your Elasticsearch credentials. This is standard Claude Desktop behavior for all extensions.

> **Kibana credentials:** `KIBANA_URL` and `KIBANA_API_KEY` are optional — they default to the Elasticsearch values. If you use the same credentials for both, you only need `ELASTICSEARCH_URL` and `ELASTICSEARCH_API_KEY`.

## Option 2: Manual config (build from source)

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
        "KIBANA_URL": "https://your-cluster.kb.cloud.example.com",
        "KIBANA_API_KEY": "your-kibana-api-key"
      }
    }
  }
}
```

Restart Claude Desktop. The tools appear under the MCP connector menu.

## Install Skills

Skills teach Claude _when_ and _how_ to use the tools. Download the skill zips from the [latest GitHub release](https://github.com/elastic/example-mcp-app-security/releases/latest):

- `alert-triage.zip`
- `attack-discovery-triage.zip`
- `case-management.zip`
- `detection-rule-management.zip`
- `generate-sample-data.zip`

In Claude Desktop: **Customize → Skills → Create Skill → Upload a skill** → upload each zip individually.

If you're building from source, generate the zips locally instead:

```bash
npm run skills:zip
# Produces dist/skills/<skill-name>.zip for each skill
```

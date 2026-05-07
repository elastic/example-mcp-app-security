# Adding to Claude Desktop

## Step 1: Install the MCP App

### Option 1: One-click install (recommended)

Download `example-mcp-app-security.mcpb` from the [latest GitHub release](https://github.com/elastic/example-mcp-app-security/releases/latest) and double-click it.

If double-click doesn't work (e.g. Claude Desktop is not associated with `.mcpb` files on your system): open Claude Desktop → **Settings → Extensions → Advanced settings → Install Extension...** → select the `.mcpb` file.

Claude Desktop installs the extension and then opens a configuration dialog. Fill in all three required fields and click **Save**:

- **Elasticsearch URL**
- **Elasticsearch API Key** — see [Creating an API key](./setup-local.md#creating-an-api-key)
- **Kibana URL**

These are assembled into a `CLUSTERS_JSON` env var for the server (the manifest takes care of this — you don't need to format JSON yourself).

> **Multi-cluster setups:** the Claude Desktop install dialog currently only exposes a single cluster. The server itself supports multi-cluster (`CLUSTERS_JSON` / `CLUSTERS_FILE`) and the dialog will gain a clusters-file picker once full multi-cluster support lands. For now, multi-cluster users should use [manual config](#option-2-manual-config-build-from-source) below or [build and run locally](./setup-local.md).

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
        "CLUSTERS_JSON": "[{\"name\":\"primary\",\"elasticsearchUrl\":\"https://your-cluster.es.cloud.example.com\",\"kibanaUrl\":\"https://your-cluster.kb.cloud.example.com\",\"elasticsearchApiKey\":\"your-api-key\"}]"
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

## Updating

### Updating the MCP App

**One-click install (.mcpb):** Download the latest `example-mcp-app-security.mcpb` from the [Releases page](https://github.com/elastic/example-mcp-app-security/releases/latest) and double-click it. Your existing configuration (Elasticsearch URL, Kibana URL, API key) is preserved — you don't need to re-enter credentials.

**Build from source:** Pull the latest code, rebuild, and install the updated `.mcpb`:

```bash
cd example-mcp-app-security
git pull
npm install
npm run build
npm run mcpb:pack
```

Then double-click the generated `.mcpb` file in `dist/` to install it. Restart Claude Desktop after updating.

### Updating skills

Skills do not need to be re-uploaded unless the release notes for a new version specifically mention skill changes. When they do, download the updated zip(s) from the release and re-upload them in Claude Desktop.

See [Updating skills](./setup-skills.md#updating-skills) for more details.

### Checking your version

Open Claude Desktop's MCP connector menu and look for the server entry — the version is shown next to the server name. You can also check the version in `manifest.json` if running from source, or compare your installed release against the [latest release](https://github.com/elastic/example-mcp-app-security/releases/latest).

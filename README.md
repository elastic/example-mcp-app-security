# Elastic Security MCP App

An [MCP App](https://modelcontextprotocol.io/extensions/apps/overview) that brings interactive blue-team security operations directly into Claude, VS Code, and other MCP-compatible AI hosts. Built on the [Model Context Protocol](https://modelcontextprotocol.io/) with interactive UI extensions that render inline in the conversation.

> **What are MCP Apps?** MCP Apps extend the Model Context Protocol to let tool servers return interactive HTML interfaces — dashboards, forms, visualizations — that render inside the AI conversation. The LLM calls a tool, and instead of just returning text, an interactive UI appears alongside the response.

## What This Does

This project provides five interactive security operations tools, each with a rich React-based UI that renders inline when Claude (or another MCP host) calls the tool:

| Tool | What It Does | UI |
|------|-------------|-----|
| **Alert Triage** | Fetch, filter, and triage security alerts | Dashboard with severity grouping, host grouping, process tree, network investigation, threat classification, and AI verdict cards |
| **Case Management** | Create, search, and manage SOC investigation cases | Case list with status filters, detail view, comment threads, status transitions |
| **Detection Rules** | Browse, tune, and manage detection rules | Rule browser with KQL search, query validation, noisy rules analysis, enable/disable |
| **Threat Hunt** | Interactive ES\|QL workbench with entity investigation graph | Query editor with auto-execute, results table with charts, and a Sentinel-style investigation graph |
| **Sample Data** | Generate ECS security events for demos and testing | Scenario picker for 4 attack chains (ransomware, credential theft, AWS escalation, Okta takeover) |

## How It Works

```
┌─────────────────────────────────────────────┐
│          MCP Host (Claude Desktop)          │
│                                             │
│  User: "Triage my ransomware alerts"        │
│           │                                 │
│           ▼                                 │
│  Claude reads the skill → calls             │
│  triage-alerts with query: "ransomware"     │
│           │                                 │
│           ▼                                 │
│  ┌─────────────────────────────────────┐    │
│  │    Interactive Alert Triage UI      │    │
│  │  ┌──────────┐ ┌──────────────────┐  │    │
│  │  │ Alert    │ │ Detail View      │  │    │
│  │  │ List     │ │ Process Tree     │  │    │
│  │  │ (grouped │ │ Network Events   │  │    │
│  │  │ by host) │ │ MITRE Mapping    │  │    │
│  │  └──────────┘ │ Classification   │  │    │
│  │               └──────────────────┘  │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  Claude: "6 ransomware alerts found.        │
│  SRVWIN02 shows active Sodinokibi           │
│  execution — classified as Malicious..."    │
└─────────────────────────────────────────────┘
          │                    ▲
          │ tools/call         │ tool result
          ▼                    │
┌─────────────────────────────────────────────┐
│         MCP App Server (this project)       │
│                                             │
│  28 tools (5 model-facing + 23 app-only)    │
│  5 interactive UI resources (React/HTML)    │
│  Elastic API client (ES + Kibana)           │
└─────────────────────────────────────────────┘
          │                    ▲
          │ REST API           │ JSON
          ▼                    │
┌─────────────────────────────────────────────┐
│            Elastic Stack                    │
│  Elasticsearch 8.x/9.x  •  Kibana          │
│  .alerts-security.alerts-*                  │
│  logs-endpoint.events.process-*             │
│  logs-endpoint.events.network-*             │
└─────────────────────────────────────────────┘
```

### The Two Types of Tools

Each capability has **model-facing tools** (the LLM decides when to call them) and **app-only tools** (the UI calls them for interactivity):

- **Model-facing** (`triage-alerts`, `manage-cases`, `manage-rules`, `threat-hunt`, `generate-sample-data`): The LLM calls these based on the user's request. Each returns a compact text summary to the LLM AND renders an interactive UI via a `ui://` resource.
- **App-only** (`poll-alerts`, `get-alert-context`, `acknowledge-alert`, `execute-esql`, `investigate-entity`, etc.): Hidden from the LLM. The UI calls these for interactivity — refreshing data, expanding graph nodes, running queries, etc.

### Skills

The `skills/` directory contains [Claude Desktop Skills](https://docs.anthropic.com/en/docs/claude-desktop/skills) — `SKILL.md` files that teach Claude *when* and *how* to use the tools effectively. These encode SOC triage methodology, classification criteria, and tool usage patterns from the [Elastic agent-skills](https://github.com/elastic/agent-skills/tree/main/skills/security) repository.

Install them via Claude Desktop's Skills UI (Settings → Skills → + → drag `.skill` file).

## Features in Detail

### Alert Triage

The crown jewel. When you say "triage my ransomware alerts", Claude:

1. Calls `triage-alerts` with `query: "ransomware"` and optionally `verdicts` (its classification per rule)
2. The UI renders a full triage dashboard:
   - **Filter bar** with query pill, severity dots, search, fullscreen toggle
   - **Summary panel** with host/rule/severity bar charts
   - **AI verdict cards** showing Claude's classification (Malicious/Suspicious/Benign) with reasoning and recommended actions
   - **Alert list grouped by host** with collapsible sections
   - **Two-pane detail view**: click any alert to see metadata, process tree, network connections, related alerts, and manual classification controls
   - **MITRE ATT&CK** tags throughout

The `verdicts` parameter lets Claude pass structured classifications that render as visual cards in the UI — bridging Claude's text analysis with interactive display.

### Threat Hunt & Investigation Graph

The threat hunt workbench combines an ES|QL query engine with a **Sentinel-style entity investigation graph**:

- **ES|QL Editor**: Claude can pre-populate and auto-execute queries. Results show in a table with a chart toggle for aggregation queries.
- **Clickable entities**: User names, hostnames, IPs, and process names in query results are clickable — click one to start a graph investigation.
- **Investigation Graph** (two views):
  - **Cards view**: Left-to-right hierarchical layout. Each entity is a card showing type, name, event count, and alert status. Click `+` to expand connections rightward. Alert-linked nodes get red borders and "INC" badges.
  - **Network view**: D3 force-directed graph with zoom/pan/drag. Entity types have distinct shapes and colors.
- **Entity expansion**: Clicking `+` runs pre-built ES|QL queries against your data to find related users, hosts, processes, IPs, and alerts. The graph grows progressively as you investigate.

### Case Management

Interactive case dashboard with Kibana Cases API integration:
- Status filters (open/in-progress/closed)
- Severity-colored cards
- Case detail with metadata grid, description, tags, status transitions, comment thread
- Create case form
- All operations use the Kibana 9.x API with proper `elastic-api-version` headers

### Detection Rules

Rule management dashboard:
- KQL search across rules
- Rule cards with severity borders, enabled/disabled indicator, MITRE tags
- Rule detail with query display, validation panel
- Noisy rules analysis (top rules by alert volume)
- Enable/disable toggle

### Sample Data Generator

Generate ECS-compliant security events for demos:
- **Windows Credential Theft**: Mimikatz, procdump, credential dumping
- **AWS Privilege Escalation**: IAM policy changes, role assumption
- **Okta Identity Takeover**: MFA factor reset, session hijacking
- **Ransomware Kill Chain**: PowerShell execution, C2, mass file encryption

All data tagged for safe cleanup.

## Prerequisites

- **Node.js 22+**
- **Elasticsearch 8.x or 9.x** with Security enabled
- **Kibana 8.x or 9.x** (for case management and detection rules)
- **API keys** for both Elasticsearch and Kibana
- **Claude Desktop**, **Claude.ai**, or another MCP-compatible host

## Quick Start

```bash
# Clone and install
git clone <repo-url>
cd mcpapp
npm install

# Configure
cp .env.example .env
# Edit .env with your Elasticsearch/Kibana URLs and API keys

# Build
npm run build

# Run (HTTP mode for testing)
npm start
# Server runs on http://localhost:3001/mcp
```

### Test with the MCP basic-host

```bash
# In a separate terminal
git clone https://github.com/modelcontextprotocol/ext-apps.git
cd ext-apps/examples/basic-host
npm install
SERVERS='["http://localhost:3001/mcp"]' npm start
# Open http://localhost:8080
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "elastic-security": {
      "command": "node",
      "args": ["/path/to/mcpapp/dist/main.js", "--stdio"],
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

Then restart Claude Desktop. The tools appear under the MCP connector menu.

### Install Skills

Build the `.skill` packages and install in Claude Desktop:

```bash
cd skills
for skill in alert-triage case-management detection-rule-management generate-sample-data; do
  zip -r ../dist/skills/${skill}.skill ${skill}/
done
```

Then in Claude Desktop: Settings → Skills → Manage Skills → drag each `.skill` file.

### VS Code

Add to `.vscode/settings.json`:

```json
{
  "mcp": {
    "servers": {
      "elastic-security": {
        "command": "node",
        "args": ["/path/to/mcpapp/dist/main.js", "--stdio"],
        "env": {
          "ELASTICSEARCH_URL": "...",
          "ELASTICSEARCH_API_KEY": "...",
          "KIBANA_URL": "...",
          "KIBANA_API_KEY": "..."
        }
      }
    }
  }
}
```

### Claude.ai (via tunnel)

```bash
npm start
npx cloudflared tunnel --url http://localhost:3001
# Add the generated URL as a custom MCP connector in Claude.ai settings
```

## Architecture

```
mcpapp/
├── main.ts                         # Entry: HTTP + stdio transport
├── src/
│   ├── server.ts                   # MCP server: registers all tools + resources
│   ├── elastic/                    # Elasticsearch/Kibana API client
│   │   ├── client.ts              # Shared fetch wrapper with auth
│   │   ├── alerts.ts              # Alert queries (fetch, search, acknowledge)
│   │   ├── cases.ts               # Kibana Cases API (CRUD, comments, attachments)
│   │   ├── rules.ts               # Detection Engine API (rules, exceptions)
│   │   ├── esql.ts                # ES|QL query execution
│   │   ├── indices.ts             # Index listing and field mappings
│   │   ├── investigate.ts         # Entity investigation queries (graph expansion)
│   │   └── sample-data.ts         # ECS event generation
│   ├── tools/                      # MCP tool definitions
│   │   ├── alert-triage.ts        # triage-alerts + poll/ack/context tools
│   │   ├── case-management.ts     # manage-cases + CRUD tools
│   │   ├── detection-rules.ts     # manage-rules + find/toggle/validate tools
│   │   ├── threat-hunt.ts         # threat-hunt + execute-esql + investigate-entity
│   │   └── sample-data.ts         # generate-sample-data + cleanup
│   ├── views/                      # React UIs (one per tool)
│   │   ├── alert-triage/          # Alert triage dashboard
│   │   ├── case-management/       # Case management dashboard
│   │   ├── detection-rules/       # Rule management dashboard
│   │   ├── threat-hunt/           # ES|QL workbench + investigation graph
│   │   └── sample-data/           # Sample data generator
│   └── shared/                     # Shared UI components
│       ├── base.css               # Design system (tokens, animations, components)
│       ├── theme.ts               # Host theme integration
│       ├── severity.tsx           # Severity badges, dots, colors
│       ├── mitre.tsx              # MITRE ATT&CK tag display
│       ├── types.ts               # TypeScript types
│       └── extract-tool-text.ts   # Tool result parsing utilities
├── skills/                         # Claude Desktop Skills
│   ├── alert-triage/              # SOC triage methodology + classification guide
│   ├── case-management/           # Case CRUD workflows
│   ├── detection-rule-management/ # Rule tuning methodology
│   └── generate-sample-data/      # Demo data workflows
├── vite.config.ts                  # Vite + React + Tailwind + single-file bundler
├── scripts/build-views.js          # Builds each view into a self-contained HTML file
└── package.json
```

### How Views Are Built

Each view is a React app bundled into a **single self-contained HTML file** using [vite-plugin-singlefile](https://github.com/niclasfin/vite-plugin-singlefile). All CSS, JavaScript, and assets are inlined. The MCP server reads these HTML files and serves them as `ui://` resources. The MCP host renders them in a sandboxed iframe.

### How the UI Communicates

The UI (React app in iframe) communicates with the MCP server through the host using `@modelcontextprotocol/ext-apps`:

- **`app.callServerTool()`**: UI calls app-only tools on the server (e.g., refresh data, run queries)
- **`app.ontoolresult`**: UI receives the tool result when the LLM calls the model-facing tool
- **`app.updateModelContext()`**: UI pushes state back to the LLM's context
- **`app.requestDisplayMode()`**: UI can request fullscreen

## Development

```bash
# Watch mode: rebuilds views and restarts server on changes
npm run dev

# Type-check only
npm run typecheck

# Build views only
npm run build:views

# Build server only
npm run build:server
```

### Adding a New View

1. Create `src/views/my-view/mcp-app.html`, `mcp-app.tsx`, `App.tsx`, `styles.css`
2. Create the tool in `src/tools/my-tool.ts` with `registerAppTool` + `registerAppResource`
3. Register in `src/server.ts`
4. The build script auto-discovers views by scanning `src/views/*/mcp-app.html`

## Key Design Decisions

### Compact Tool Results

Model-facing tools return **compact summaries** (~1-5KB) to the LLM, not full Elasticsearch documents (which can be 800KB+). Claude Desktop enforces a 1MB limit on tool results. The UI independently loads full data via app-only tools.

### Self-Loading UI

The UI doesn't rely on `ontoolresult` for its primary data. It self-loads via `callServerTool("poll-alerts", ...)` after connecting. The `ontoolresult` callback is used only to extract filter parameters (query, severity) and verdicts from the LLM's tool call.

### Intent-Aware Filtering

The `triage-alerts` tool accepts a `query` parameter. When the user says "triage my ransomware alerts", Claude passes `query: "ransomware"` and the server filters alerts server-side using Elasticsearch wildcard queries across rule name, reason, host, user, process, and file path fields.

### AI Verdict Integration

The `triage-alerts` tool accepts an optional `verdicts` array in its input schema. Claude can include structured classifications (rule, classification, confidence, summary, action) which the UI renders as visual verdict cards. This bridges Claude's text analysis with interactive display.

### Investigation Graph

The threat hunt view includes an entity investigation graph inspired by Microsoft Sentinel. Clicking `+` on an entity node calls `investigate-entity`, which runs pre-built ES|QL `STATS ... BY` queries to find related entities. The graph supports two layouts:
- **Cards**: Left-to-right tree layout for progressive investigation
- **Network**: D3 force-directed graph for relationship overview

### Kibana 9.x Compatibility

All Kibana API calls include `elastic-api-version: 2023-10-31` headers and use camelCase field names (e.g., `createdAt` not `created_at`) for compatibility with Kibana 9.x.

## Inspired By

- [Elastic Agent Skills](https://github.com/elastic/agent-skills/tree/main/skills/security) — SOC triage methodology, case management workflows, detection rule tuning patterns
- [MCP Apps Specification](https://modelcontextprotocol.io/extensions/apps/overview) — Interactive UI extensions for the Model Context Protocol
- [Microsoft Sentinel Investigation Graph](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases) — Entity-centric investigation UX

## License

Apache-2.0

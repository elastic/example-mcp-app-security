# Elastic Security MCP App

An [MCP App](https://modelcontextprotocol.io/extensions/apps/overview) that brings interactive blue-team security operations directly into Claude, VS Code, and other MCP-compatible AI hosts. Built on the [Model Context Protocol](https://modelcontextprotocol.io/) with interactive UI extensions that render inline in the conversation.

> **What are MCP Apps?** MCP Apps extend the Model Context Protocol to let tool servers return interactive HTML interfaces — dashboards, forms, visualizations — that render inside the AI conversation. The LLM calls a tool, and instead of just returning text, an interactive UI appears alongside the response.

![Alert Triage Dashboard](docs/screenshots/alert-triage.png)

## What This Does

This project provides six interactive security operations tools, each with a rich React-based UI that renders inline when Claude (or another MCP host) calls the tool:

| Tool | What It Does |
|------|-------------|
| **Alert Triage** | Fetch, filter, and triage security alerts with AI verdict cards, process tree, and network investigation |
| **Attack Discovery** | AI-powered correlated attack chain analysis with confidence scoring, entity risk, and MITRE mapping |
| **Case Management** | Create, search, and manage SOC investigation cases with AI-assisted actions |
| **Detection Rules** | Browse, tune, and manage detection rules with KQL search and noisy rules analysis |
| **Threat Hunt** | ES\|QL workbench with clickable entities and a D3 investigation graph |
| **Sample Data** | Generate ECS security events for demos across 4 attack chain scenarios |

See [docs/features.md](docs/features.md) for a full breakdown of each tool's capabilities.

## How It Works

![Interaction Flow](docs/screenshots/interaction-flow.png)

When a user asks Claude to triage alerts or run a threat hunt, Claude calls a model-facing tool on this server. The tool returns a compact text summary to Claude **and** an interactive React UI that renders inline in the conversation. The UI then calls app-only tools directly for all subsequent interactions — keeping the LLM context small while the UI has full data access.

See [docs/architecture.md](docs/architecture.md) for details on how views are built, how the UI communicates with the server, and key design decisions.

### Skills

The `skills/` directory contains [Claude Skills](https://claude.com/docs/skills/overview) — `SKILL.md` files that teach Claude *when* and *how* to use the tools. See [docs/setup-skills.md](docs/setup-skills.md) for installation instructions.

## Installation

| Guide | Description |
|-------|-------------|
| [Add to Claude Desktop](docs/setup-claude-desktop.md) | Install the MCP app via one-click `.mcpb` or manual config |
| [Add to Cursor](docs/setup-cursor.md) | Connect the MCP app via npx or a locally running server |
| [Add to VS Code](docs/setup-vscode.md) | Connect the MCP app via npx or a locally running server |
| [Add to Claude Code](docs/setup-claude-code.md) | Register the MCP app via the `claude mcp add` CLI |
| [Add to Claude.ai](docs/setup-claude-ai.md) | Expose the MCP app via a cloudflared tunnel |
| [Build and run locally](docs/setup-local.md) | Build the MCP server from source and run it on your machine |
| [Install skills](docs/setup-skills.md) | Install skills via npx, local clone, or zip upload |

## Development

```bash
npm run dev          # Watch mode
npm run typecheck    # Type-check only
npm run build:views  # Build views only
npm run build:server # Build server only
```

## Inspired By

- [Elastic Agent Skills](https://github.com/elastic/agent-skills/tree/main/skills/security) — SOC triage methodology and tool patterns
- [MCP Apps Specification](https://modelcontextprotocol.io/extensions/apps/overview) — Interactive UI extensions for MCP

## License

Elastic-2.0

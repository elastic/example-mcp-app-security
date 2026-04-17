# Architecture

## The Two Types of Tools

- **Model-facing** (`triage-alerts`, `triage-attack-discoveries`, `manage-cases`, `manage-rules`, `threat-hunt`, `generate-sample-data`, `generate-attack-discovery`): The LLM calls these. Each returns a compact text summary AND renders an interactive UI.
- **App-only** (`poll-alerts`, `get-alert-context`, `investigate-entity`, `get-entity-detail`, `execute-esql`, `get-case-alerts`, `get-case-comments`, etc.): Hidden from the LLM. The UI calls these for interactivity.

## How Views Are Built

Each view is a React app bundled into a **single self-contained HTML file** using [vite-plugin-singlefile](https://github.com/niclasfin/vite-plugin-singlefile). All CSS, JavaScript, and assets are inlined. The MCP server reads these HTML files and serves them as `ui://` resources. The MCP host renders them in a sandboxed iframe.

## How the UI Communicates

The UI (React app in iframe) communicates with the MCP server through the host:

- **`app.callServerTool()`**: UI calls app-only tools on the server
- **`app.ontoolresult`**: UI receives the tool result when the LLM calls the model-facing tool
- **`app.ontoolinput`**: UI receives tool arguments as the LLM generates them (used for verdict streaming)
- **`app.updateModelContext()`**: UI pushes state back to the LLM's context
- **`app.sendMessage()`**: UI sends messages to the conversation (used for AI case actions)
- **`app.requestDisplayMode()`**: UI can request fullscreen

## Key Design Decisions

### Compact Tool Results
Model-facing tools return **compact summaries** (~1-5KB) to the LLM, not full Elasticsearch documents (800KB+). The UI independently loads full data via app-only tools.

### Self-Loading UI
The UI self-loads via `callServerTool` after connecting. The `ontoolresult` callback extracts filter parameters and verdicts from the LLM's tool call.

### Intent-Aware Filtering
Multi-word search uses OR logic: "ransomware SRVWIN" matches alerts where any field contains "ransomware" OR "SRVWIN".

### AI Verdict Integration
The `triage-alerts` tool accepts an optional `verdicts` array. Claude passes structured classifications that render as visual cards in the UI.

### Progressive Investigation Graph
The graph starts with a single node. Click `+` to expand — each expansion runs pre-built ES|QL `STATS ... BY` queries. Hover to trace connections, drag to reposition, click for entity details from ES.

### Attack Discovery On-Demand
The `generate-attack-discovery` tool triggers Kibana's Attack Discovery API with any AI connector. Progress is polled via `/api/attack_discovery/generations` and shown as Kibana-style banners.

### Kibana 9.x Compatibility
All Kibana API calls include `elastic-api-version: 2023-10-31` headers, `x-elastic-internal-origin: Kibana` for internal APIs, and camelCase field names.

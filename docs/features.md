# Features in Detail

## Alert Triage

The primary SOC workflow. Claude acts as a senior analyst:

- **Intent-aware filtering**: "triage ransomware alerts" → filters by rule name, host, user, process with OR logic
- **AI verdict cards**: Claude can pass structured classifications per rule that render as colored cards
- **Summary panel**: host/rule/severity bar charts at a glance
- **Alert list grouped by host**: collapsible sections, severity-colored left borders
- **Two-pane detail view**: click any alert for metadata, process tree, network events, related alerts
- **Threat classifier**: Benign/Suspicious/Malicious buttons that auto-create cases and attach alerts
- **MITRE ATT&CK tags** throughout
- **Fullscreen toggle** and search

## Attack Discovery

AI-powered correlated attack chain analysis using Elastic's Attack Discovery API:

- **On-demand generation**: "run attack discovery using Opus 4.6" triggers analysis via any AI connector
- **Progress banners**: blue spinner during generation, green success when complete (Kibana-style)
- **Confidence scoring**: each finding scored by alert diversity, rule frequency, entity risk
- **Attack flow diagrams**: visual entity relationship graphs per finding
- **MITRE tactics mapping**: colored pills for each tactic in the kill chain
- **Approve/reject workflows**: bulk triage discovered attacks
- **Auto-polling**: refreshes every 10s during active generation

## Threat Hunt & Investigation Graph

ES|QL query workbench with a Sentinel-style entity investigation graph:

- **Auto-execute**: Claude's pre-populated queries run immediately
- **Clickable entities**: user.name, host.name, IPs, process.name in results are clickable links
- **Progressive graph**: click `+` to expand one entity at a time — you control the investigation path
- **Two graph views**: Cards (left-to-right tree) and Network (D3 force-directed)
- **Hover-to-trace**: hover a node to highlight only its direct connections, everything else dims
- **Draggable nodes**: reposition nodes with edges following in real-time
- **Entity detail panel**: click a node to see real ES data (alert details, process info, network connections, activity timeline)
- **Alert highlighting**: nodes connected to alerts get red dashed rings
- **Charts**: Table/Chart toggle for aggregation queries
- **Overflow groups**: "+N more" for entity types with many connections

## Case Management

Interactive case dashboard with the Kibana Cases API:

- **Tabbed detail view**: Overview (markdown-rendered), Alerts (fetched from ES with full details), Observables (hashes, IPs, domains), Comments (with avatars and markdown)
- **Case IDs**: `#42` visible in list and detail
- **AI-generated avatars**: unique geometric SVG identicons per user
- **Markdown rendering**: case descriptions and comments rendered as rich HTML
- **AI action buttons**: Summarize case, Suggest next steps, Extract IOCs, Generate timeline — each sends a prompt to Claude via `app.sendMessage`
- **Auto-attach alerts**: classifying an alert creates a case AND attaches the alert
- **Summary stats bar**: Total, Open, In Progress, High/Critical counts
- **Refresh button** and fullscreen toggle

## Detection Rules

Rule management dashboard:

- KQL search, severity borders, enabled/disabled indicator, MITRE tags
- Rule detail with query block, validation panel
- Noisy rules analysis (top rules by alert volume with bar chart)
- Enable/disable toggle

## Sample Data Generator

Generate ECS-compliant security events:
- Windows Credential Theft, AWS Privilege Escalation, Okta Identity Takeover, Ransomware Kill Chain
- All data tagged for safe cleanup

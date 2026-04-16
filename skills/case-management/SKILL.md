---
name: case-management
description: >
  Create, search, update, and manage SOC cases for Elastic Security. ALWAYS use this
  skill when the user mentions cases, incidents, investigations, or asks to see, show,
  list, open, create, update, or search cases. Trigger for: "show me my cases",
  "open cases", "list cases", "any open cases", "create a case", "case for this alert",
  "show me case 42", "incident tracking", "investigation status", or any case-related question.
---

# Case Management

Manage SOC cases using the `elastic-security` MCP connector.

## ALWAYS call the tool

When the user asks about cases, ALWAYS call `manage-cases` to open the interactive dashboard.
Do not try to answer from memory or describe cases without calling the tool first.

| User says | Tool call |
|-----------|-----------|
| "show me my cases" | `manage-cases` (no params) |
| "any open cases?" | `manage-cases` with `status: "open"` |
| "closed cases" | `manage-cases` with `status: "closed"` |
| "cases for SRVWIN02" | `manage-cases` with `search: "SRVWIN02"` |
| "critical cases" | `manage-cases` with `severity: "critical"` |
| "show case 42" | `manage-cases` (user can click it in the dashboard) |
| "create a case" | `create-case` with title, description, tags, severity |
| "create a case for this alert" | `create-case` with alert details, then `attach-alert-to-case` |

## Tools

| Tool | Purpose |
|------|---------|
| `manage-cases` | Opens interactive case dashboard. Params: `status`, `severity`, `search` |
| `create-case` | Creates a new case. Params: `title`, `description`, `tags` (comma-separated), `severity` |
| `attach-alert-to-case` | Attaches an alert to a case. Params: `caseId`, `alertId`, `alertIndex`, `ruleId`, `ruleName` |
| `update-case` | Updates case status/severity. Params: `caseId`, `version`, `status`, `severity` |
| `add-case-comment` | Adds investigation notes. Params: `caseId`, `comment` |

## Creating Cases

When the user asks you to create a case, call `create-case` directly — do NOT tell them to use the dashboard UI.

Example:
```
create-case with:
  title: "[MALICIOUS] Ransomware Attack Chain — srv-win-defend-01"
  description: "## Summary\n- Full ransomware kill chain detected\n- Host: srv-win-defend-01\n- User: Jonathan\n\n## MITRE ATT&CK\nT1566, T1059, T1218\n\n## Findings\n..."
  tags: "classification:malicious,confidence:high,host:srv-win-defend-01,mitre:T1566,mitre:T1059"
  severity: "critical"
```

After creating the case, if you have alert IDs, attach them with `attach-alert-to-case`.

## Tag Conventions

| Tag pattern | Example | Purpose |
|-------------|---------|---------|
| `classification:<level>` | `classification:malicious` | Triage result |
| `confidence:<score>` | `confidence:85` | Confidence 0-100 |
| `mitre:<technique>` | `mitre:T1574.002` | MITRE ATT&CK technique |
| `agent_id:<uuid>` | `agent_id:550888e5-...` | Elastic agent ID |
| `rule:<name>` | `rule:Malware Detection` | Detection rule name |

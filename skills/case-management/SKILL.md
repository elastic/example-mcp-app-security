---
name: elastic-security-case-management
description: >
  Create, search, update, and manage SOC cases for Elastic Security. Use when tracking
  incidents, creating cases from triage findings, linking alerts to cases, adding
  investigation notes, or managing case status. Also trigger for "create a case",
  "open cases", "incident tracking", or any case management question.
---

# Case Management

Manage SOC cases using the `elastic-security` MCP connector. The `manage-cases` tool renders an interactive case
management dashboard.

## Tools (via elastic-security MCP connector)

| Tool | Purpose |
|------|---------|
| `manage-cases` | Browse/search cases with interactive dashboard. Params: `status`, `severity`, `search` |

The dashboard supports creating cases, updating status, adding comments, and attaching alerts — all from the UI.

## Workflows

| Task | How |
|------|-----|
| View open cases | `manage-cases` with `status: "open"` |
| Find cases for a host | `manage-cases` with `search: "<hostname>"` |
| Create a case | Use the "+ New Case" button in the dashboard |
| Update case status | Click into a case, use status transition buttons |

## Tag Conventions

Use structured tags for machine-searchable metadata:

| Tag pattern | Example | Purpose |
|-------------|---------|---------|
| `classification:<level>` | `classification:malicious` | Triage result |
| `confidence:<score>` | `confidence:85` | Confidence 0-100 |
| `mitre:<technique>` | `mitre:T1574.002` | MITRE ATT&CK technique |
| `agent_id:<uuid>` | `agent_id:550888e5-...` | Elastic agent ID |
| `rule:<name>` | `rule:Malware Detection` | Detection rule name |

## Case Severity Mapping

| Classification | Severity |
|---------------|----------|
| Benign (score 0-19) | low |
| Suspicious (score 20-60) | medium |
| Malicious (score 61-80) | high |
| Malicious (score 81-100) | critical |

---
name: detection-rule-management
description: >
  Create, tune, and manage Elastic Security detection rules. Use for false positive
  tuning, adding exceptions, creating new detection coverage, finding noisy rules,
  enabling/disabling rules, or any detection engineering task. Also trigger for
  "detection rules", "noisy rules", "false positives", "add exception", "create rule",
  or "tune rule".
---

# Detection Rule Management

Manage detection rules using the `elastic-security` MCP connector. The `manage-rules` tool renders an interactive
rule management dashboard.

## Tools (via elastic-security MCP connector)

| Tool | Purpose |
|------|---------|
| `manage-rules` | Browse/search rules with interactive dashboard. Params: `filter` (KQL) |
| `threat-hunt` | Test queries against live data before creating rules |

The dashboard supports searching rules, viewing details, enabling/disabling, validating queries, and viewing noisy rules.

## Rule Types

| Type | Use case | Example |
|------|----------|---------|
| `query` (KQL) | Simple field matching | `process.name: "mimikatz.exe"` |
| `eql` | Behavioral sequences | Process A spawns B within 5 minutes |
| `esql` | Analytics/aggregations | Complex joins or transformations |
| `threshold` | Count/frequency | >10 failed logins in 5 minutes |
| `threat_match` | IOC correlation | Match against malicious IP indicators |
| `new_terms` | First-time activity | User logs into host for first time |

## Tuning Strategy (in order of preference)

1. **Add exception** — Known-good process/user/host. Does not modify the rule query.
2. **Tighten the query** — Exclude FP pattern from the rule query itself.
3. **Adjust threshold/suppression** — Increase threshold or enable alert suppression.
4. **Reduce risk score/severity** — Downgrade priority if rule has some value but is noisy.
5. **Disable the rule** — Last resort. Only if rule provides no value.

## Creating New Rules

1. Define the threat (MITRE technique, data sources, malicious vs legitimate behavior)
2. Test the query with `threat-hunt` against live data
3. Create via the dashboard or ask Claude to help construct the rule JSON
4. Monitor alert volume and tune false positives

## Common Index Patterns

| Data type | Index pattern |
|-----------|--------------|
| Alerts | `.alerts-security.alerts-*` |
| Processes | `logs-endpoint.events.process-*` |
| Network | `logs-endpoint.events.network-*` |
| Windows | `logs-windows.*` |
| AWS | `logs-aws.*` |
| Okta | `logs-okta.*` |

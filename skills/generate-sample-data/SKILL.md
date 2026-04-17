---
name: generate-sample-data
description: >
  Generate sample security events, attack scenarios, and synthetic alerts for Elastic
  Security. Use when demoing, populating dashboards, testing detection rules, setting
  up a POC, or when the user asks for test data, demo data, or sample alerts.
---

# Generate Security Sample Data

Generate ECS-compliant security events and synthetic alerts using the `elastic-security` MCP connector.

## Tools (via elastic-security MCP connector)

| Tool | Purpose |
|------|---------|
| `generate-sample-data` | Generate events with interactive UI. Params: `scenario`, `count` |

## Attack Scenarios

| Scenario | Description |
|----------|-------------|
| `windows-credential-theft` | Mimikatz, procdump, credential dumping on Windows |
| `aws-privilege-escalation` | IAM policy changes, role assumption, access key creation |
| `okta-identity-takeover` | MFA factor reset, password change, session hijacking |
| `ransomware-kill-chain` | PowerShell execution, C2 beaconing, mass file encryption |

## Usage

- To generate all scenarios: call `generate-sample-data` without a scenario parameter
- To generate a specific scenario: pass `scenario: "ransomware-kill-chain"`
- All data is tagged with `elastic-security-sample-data` for safe cleanup
- The dashboard UI has a cleanup button to remove all generated data

## After Generating

Direct the user to explore in Kibana:
- **Security > Alerts** — synthetic alerts with MITRE ATT&CK mappings
- **Security > Attack Discovery** — requires an LLM connector
- **Security > Hosts** — host activity from sample events

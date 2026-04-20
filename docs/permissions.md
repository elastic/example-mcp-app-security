# Recommended Minimum Permissions

Use these permissions as a practical least-privilege baseline if you want the full app to work without creating a `superuser` API key.

Exact privilege names vary a bit by Elastic Stack version, especially around the newer split Security feature privileges. The guidance below is intended to cover all app features: alerts, cases, rules, threat hunting, attack discovery, and sample data.

## Kibana Privileges

In the target Kibana space, grant:

- `Cases: All`
- `Security > Attack discovery: All`
- `Security > Rules, Alerts, and Exceptions: All`

If your version exposes split Security privileges instead, use:

- `Security > Rules and Exceptions: All`
- `Security > Alerts: All`
- `Security > Attack discovery: All`

For AI-backed attack discovery flows, also grant:

- `Actions and Connectors: Read` to use existing connectors
- `Elastic AI Assistant for Security: All`

Use `Actions and Connectors: All` only if the same user also needs to create or manage connectors.

## Elasticsearch Privileges

### Cluster

- `monitor`

### Read access

Grant `read` and `view_index_metadata` on:

- `logs-*`
- `.alerts-security.alerts-*`
- `risk-score.risk-score-latest-*`
- `.alerts-security.attack.discovery.alerts-*`
- `.internal.alerts-security.attack.discovery.alerts-*`
- `.adhoc.alerts-security.attack.discovery.alerts-*`
- `.internal.adhoc.alerts-security.attack.discovery.alerts-*`

### Alert and discovery status changes

To acknowledge alerts and update attack discovery findings, also grant write-capable access on the alert indices above:

- `.alerts-security.alerts-*`: `write`
- Attack discovery alert indices: `write` and `maintenance`

### Sample data generation

If you plan to use the Sample Data tool, also grant:

- `write`
- `create_index` or `auto_configure`
- `delete`

on:

- `logs-*-default`
- `.alerts-security.alerts-default`

This covers bulk indexing, creating sample target indices, and cleanup via `delete_by_query`.

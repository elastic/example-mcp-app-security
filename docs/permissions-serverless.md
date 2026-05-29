# Permissions — Elastic Cloud Serverless (Security project)

This guide covers the MCP app on **Elastic Cloud Serverless Security projects**. Serverless ships a curated set of built-in role identities; you can also create custom roles if the built-ins don't fit.

> **Stateful deployments:** See [permissions.md](./permissions.md) for self-managed and Elastic Cloud Hosted.

---

## Built-in role identities

Serverless Security projects pre-provision role-specific users in the file realm. You don't create or configure them — they're ready to use. Below is the observed behavior of three representative tiers against all MCP app operations.

### Role tier summary

| Operation | `t1_analyst` | `t2_analyst` | `soc_manager` |
|---|:---:|:---:|:---:|
| **Alerts** | | | |
| Fetch alerts | ✓ | ✓ | ✓ |
| Acknowledge alert | ✓ | ✓ | ✓ |
| Get alert context | ✓ | ✓ | ✓ |
| Endpoint events readable | ✓ | ✓ | ✓ |
| **Cases** | | | |
| List cases | ✓ | ✓ | ✓ |
| Get case | ✓ | ✓ | ✓ |
| Create case | ✗ | ✓ | ✓ |
| Update case | ✗ | ✓ | ✓ |
| Add comment | ✗ | ✓ | ✓ |
| Attach alert to case | ✗ | ✓ | ✓ |
| **Rules** | | | |
| Find rules | ✓ | ✓ | ✓ |
| Noisy rules | ✓ | ✓ | ✓ |
| Create rule | ✗ | ✗ | ✓ |
| Patch rule | ✗ | ✗ | ✓ |
| Bulk rule action | ✗ | ✗ | ✓ |
| List exceptions | ✓ | ✓ | ✓ |
| Add exception | ✗ | ✗ | ✓ |
| **Attack Discovery** | | | |
| Fetch discoveries | ✓ | ✓ | ✓ |
| List AI connectors | ✓ | ✓ | ✓ |
| Assess confidence | ✓ | ✓ | ✓ |
| Get discovery detail | ✓ | ✓ | ✓ |
| Acknowledge discoveries | ✓ | ✓ | ✓ |
| **Threat Hunt** | | | |
| Execute ES\|QL | ✓ | ✓ | ✓ |
| List indices (`_cat/indices`) | ✗ | ✗ | ✗ |
| Get field mapping | ✗ | ✗ | ✓ |
| **Sample Data** | | | |
| Check existing data | ✓ | ✓ | ✓ |
| Generate sample data | ✗ | ✗ | ✓ |
| Cleanup sample data logs | ✗ | ✗ | ✓ |
| Cleanup sample data alerts | ✓ | ✓ | ✓ |

### Role capability profiles

**`t1_analyst`** — read-only across all Security surfaces. Can read and acknowledge alerts, view cases and rules, run ES|QL queries, and access Attack Discovery. Cannot write cases, create or modify rules, list raw index names, or generate sample data. Closest stateful equivalent: `viewer` + alert-write index privileges.

**`t2_analyst`** — adds full case management on top of `t1_analyst`. Can create, update, and comment on cases and attach alerts to cases. Still cannot manage rules or list indices. Closest stateful equivalent: `editor` on Cases only, `viewer` on everything else.

**`soc_manager`** — full operational access. Can manage rules (create, patch, bulk actions), add exceptions, generate and clean up sample data, and get field mappings. The one gap shared with all tiers is `listIndices` — `_cat/indices` is restricted by the cluster privilege `read_project_routing` that Serverless built-ins hold (not `monitor`).

### `listIndices` limitation

All built-in Serverless Security roles use `cluster: read_project_routing` rather than the `cluster: monitor` privilege that stateful deployments use. `_cat/indices/<pattern>` requires `monitor`, so the index-picker in the Threat Hunt tool cannot enumerate available indices for any built-in role. Workaround: use a [custom role](#custom-roles) that includes `cluster: monitor`.

---

## Connecting with a built-in role identity

Serverless file-realm users can't use Basic auth with the MCP app directly — the app requires an API key. Mint a scoped key via the `grant_api_key` endpoint as the `elastic_serverless` admin:

```bash
# In Dev Tools or via curl (replace <role> with t1_analyst, t2_analyst, soc_manager, etc.)
POST /_security/api_key/grant
{
  "grant_type": "password",
  "username": "<role>",
  "password": "changeme",
  "api_key": { "name": "mcp-app-<role>" }
}
```

Use the `encoded` value from the response as `elasticsearchApiKey` in your cluster config.

> **Password:** All local serverless dev-stack file-realm users share password `changeme` (set in `kbn-es/src/serverless_resources/users`). On an actual Elastic Cloud Serverless project, users authenticate via SSO — use your cloud API key instead of the grant flow.

---

## Custom roles

Custom roles are supported on Serverless Security projects (GA since October 2024). Use `PUT /_security/role/<name>` via Dev Tools as `elastic_serverless`. The Kibana feature privilege names on serverless differ slightly from stateful 9.4+:

| Feature | Serverless privilege (all/read) |
|---|---|
| SIEM | `feature_siemV5.all` / `feature_siemV5.read` |
| Cases | `feature_securitySolutionCasesV3.all` / `feature_securitySolutionCasesV3.read` |
| Rules | `feature_securitySolutionRulesV2.all` / `feature_securitySolutionRulesV2.read` |
| Alerts | `feature_securitySolutionAlertsV1.all` / `feature_securitySolutionAlertsV1.read` |
| AI Assistant | `feature_securitySolutionAssistant.all` / `feature_securitySolutionAssistant.read` |
| Attack Discovery | `feature_securitySolutionAttackDiscovery.all` / `feature_securitySolutionAttackDiscovery.read` |
| Timeline | `feature_securitySolutionTimeline.all` / `feature_securitySolutionTimeline.read` |
| Notes | `feature_securitySolutionNotes.all` / `feature_securitySolutionNotes.read` |
| Actions/Connectors | `feature_actions.all` / `feature_actions.read` |

Note: `feature_securitySolutionRulesV2` on serverless vs `feature_securitySolutionRulesV4` on stateful 9.4+.

### Full-access custom role (serverless)

```
PUT /_security/role/mcp_app_full_serverless
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": [
        ".alerts-security.alerts-default",
        ".alerts-security.attack.discovery.alerts-default",
        ".adhoc.alerts-security.attack.discovery.alerts-default",
        ".internal.alerts-security.alerts-default-*",
        ".internal.alerts-security.attack.discovery.alerts-default-*",
        ".internal.adhoc.alerts-security.attack.discovery.alerts-default-*",
        "logs-*",
        "risk-score.risk-score-latest-*"
      ],
      "privileges": ["read", "write", "monitor", "view_index_metadata"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": [
        "feature_siemV5.all",
        "feature_securitySolutionCasesV3.all",
        "feature_securitySolutionTimeline.all",
        "feature_securitySolutionNotes.all",
        "feature_securitySolutionRulesV2.all",
        "feature_securitySolutionAlertsV1.all",
        "feature_securitySolutionAssistant.all",
        "feature_securitySolutionAttackDiscovery.all",
        "feature_actions.all"
      ],
      "resources": ["space:default"]
    }
  ]
}
```

Adding `cluster: monitor` fixes the `listIndices` gap that all built-in roles share.

### Read-only custom role (serverless)

```
PUT /_security/role/mcp_app_readonly_serverless
{
  "cluster": [],
  "indices": [
    {
      "names": [
        ".alerts-security.alerts-default",
        ".alerts-security.attack.discovery.alerts-default",
        ".adhoc.alerts-security.attack.discovery.alerts-default",
        ".internal.alerts-security.alerts-default-*",
        ".internal.alerts-security.attack.discovery.alerts-default-*",
        ".internal.adhoc.alerts-security.attack.discovery.alerts-default-*",
        "logs-*",
        "risk-score.risk-score-latest-*"
      ],
      "privileges": ["read", "view_index_metadata"]
    }
  ],
  "applications": [
    {
      "application": "kibana-.kibana",
      "privileges": [
        "feature_siemV5.read",
        "feature_securitySolutionCasesV3.read",
        "feature_securitySolutionTimeline.read",
        "feature_securitySolutionNotes.read",
        "feature_securitySolutionRulesV2.read",
        "feature_securitySolutionAlertsV1.read",
        "feature_securitySolutionAssistant.read",
        "feature_securitySolutionAttackDiscovery.read",
        "feature_actions.read"
      ],
      "resources": ["space:default"]
    }
  ]
}
```

---

## Running the permissions test matrix locally

Prerequisites: local Kibana serverless running (see [Development setup](#development-setup)).

```bash
# From example-mcp-app-security/
NODE_TLS_REJECT_UNAUTHORIZED=0 \
ELASTICSEARCH_URL=https://localhost:9200 \
KIBANA_URL=http://localhost:5601 \
npm run test:permissions:serverless
```

This exercises `t1_analyst`, `t2_analyst`, and `soc_manager` in observe-only mode (no assertions — the script reports what actually happens rather than failing on deviations). Add `--verbose` for fixture details.

To also run the asserted custom roles (`full`/`readonly`) against serverless:

```bash
NODE_TLS_REJECT_UNAUTHORIZED=0 \
ELASTICSEARCH_URL=https://localhost:9200 \
KIBANA_URL=http://localhost:5601 \
npm run test:permissions:serverless:all
```

---

## Development setup

```bash
# In kibana-main
yarn es serverless --projectType=security   # ES on https://localhost:9200
yarn start --serverless=security            # Kibana on http://localhost:5601 (no basepath)

# Admin credentials
# username: elastic_serverless  password: changeme
```

ES uses a self-signed certificate locally — set `NODE_TLS_REJECT_UNAUTHORIZED=0` when running the test runner or any `curl` commands.

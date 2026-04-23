# Minimum Required Permissions

This guide defines the least-privilege roles for the Elastic Security MCP app. Two pre-built roles cover most use cases:

- **Full-featured** — all tools, read and write operations
- **Read-only** — view alerts, cases, rules, and discoveries without making changes

For custom roles, see the [per-tool privilege breakdown](#appendix-per-tool-privilege-breakdown) at the end.

> **Space ID:** Kibana index patterns include a `<space-id>` segment (e.g., `.alerts-security.alerts-<space-id>`). For most deployments this is `default`. Replace `<space-id>` with your actual space ID throughout this guide.
>
> The app currently targets the `default` space.

---

## Quick Reference

| Privilege area | Full-featured | Read-only |
|---|---|---|
| **Cluster** | `monitor` | `monitor` |
| **System indices** (`.alerts-*`) | `read`, `write` | `read` |
| **Data indices** (`logs-*`, `risk-score.*`) | `read`, `write` | `read` |
| **Kibana features** | All on most Security features | Read on core Security features |
| **Attack Discovery** | Yes | No |
| **Case creation/updates** | Yes | No |
| **Alert acknowledgment** | Yes | No |
| **Rule management** | Yes | No |

---

## Full-Featured Role

### Cluster privileges

| Privilege | Why |
|---|---|
| `monitor` | `_cat/indices` for Threat Hunt, AI Assistant prerequisite |

### Index privileges

**System / alert indices** (`read`, `write`):

| Index pattern | Used by |
|---|---|
| `.alerts-security.alerts-<space-id>` | Alert Triage, Attack Discovery, Detection Rules, Case Management, Sample Data cleanup |
| `.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery |
| `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery (ad-hoc generated) |

**Data indices** (`read`, `write`):

| Index pattern | Used by |
|---|---|
| `logs-*` | Threat Hunt, Alert Triage (enrichment), Sample Data (write + cleanup) |
| `risk-score.risk-score-latest-*` | Attack Discovery (entity risk scoring) |

### Kibana feature privileges

<details open>
<summary><strong>9.4+</strong> (recommended)</summary>

| Feature | Privilege | Why |
|---|---|---|
| Security > Security | All | Base access gate |
| Security > Cases | All | Case CRUD |
| Security > Timeline | All | Investigation timelines |
| Security > Notes | All | Timeline notes |
| Security > Rules and Exceptions | All | Rule CRUD, Attack Discovery prerequisite |
| Security > Alerts | All | Alert triage, Attack Discovery prerequisite |
| Security > Elastic AI Assistant | All | Anonymization fields for Attack Discovery |
| Security > Attack discovery | All | Generate/view/acknowledge discoveries |
| Management > Actions and Connectors | All | AI connector execution for Attack Discovery |

</details>

<details>
<summary><strong>9.3</strong> (diff from 9.4+)</summary>

- "Rules and Exceptions" and "Alerts" are combined into a single **"Rules, Alerts, and Exceptions"** feature — grant **All**
- All other features remain the same

</details>

<details>
<summary><strong>9.0 - 9.2</strong> (diff from 9.4+)</summary>

- Rules, Alerts, and Exceptions are all part of the base **"Security"** feature — grant **All**
- No separate Rules or Alerts features exist
- All other features remain the same

</details>

### Dev Tools: Create the role

```
PUT /_security/role/mcp_app_full
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": [
        ".alerts-security.alerts-<space-id>",
        ".alerts-security.attack.discovery.alerts-<space-id>",
        ".adhoc.alerts-security.attack.discovery.alerts-<space-id>",
        "logs-*",
        "risk-score.risk-score-latest-*"
      ],
      "privileges": ["read", "write"]
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
        "feature_securitySolutionRulesV4.all",
        "feature_securitySolutionAlertsV1.all",
        "feature_securitySolutionAssistant.all",
        "feature_securitySolutionAttackDiscovery.all",
        "feature_actions.all"
      ],
      "resources": ["space:<space-id>"]
    }
  ]
}
```

> Replace `<space-id>` with your Kibana space ID (typically `default`).

### Kibana UI walkthrough

1. Go to **Stack Management > Roles > Create role**
2. Under **Cluster privileges**, add `monitor`
3. Under **Index privileges**, add the index patterns and select `read` + `write`
4. Under **Kibana privileges**, select the space and grant **All** to each feature listed above
5. Save the role

### Create an API key scoped to this role

```
POST /_security/api_key
{
  "name": "mcp-app-full",
  "role_descriptors": {
    "mcp_app_full": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": [
            ".alerts-security.alerts-<space-id>",
            ".alerts-security.attack.discovery.alerts-<space-id>",
            ".adhoc.alerts-security.attack.discovery.alerts-<space-id>",
            "logs-*",
            "risk-score.risk-score-latest-*"
          ],
          "privileges": ["read", "write"]
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
            "feature_securitySolutionRulesV4.all",
            "feature_securitySolutionAlertsV1.all",
            "feature_securitySolutionAssistant.all",
            "feature_securitySolutionAttackDiscovery.all",
            "feature_actions.all"
          ],
          "resources": ["space:default"]
        }
      ]
    }
  }
}
```

The response includes an `encoded` field — use that as your `ELASTICSEARCH_API_KEY`.

---

## Read-Only Role

A strict read-only role: view everything, change nothing.

> Need to acknowledge alerts or create cases? Use the full-featured role, or build a custom role using the [per-tool privilege breakdown](#appendix-per-tool-privilege-breakdown).

### Cluster privileges

| Privilege | Why |
|---|---|
| `monitor` | `_cat/indices` for Threat Hunt |

### Index privileges

**All index patterns** (`read` only):

| Index pattern | Used by |
|---|---|
| `.alerts-security.alerts-<space-id>` | Alert Triage, Detection Rules, Case viewing |
| `.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery viewing |
| `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery viewing |
| `logs-*` | Threat Hunt, Alert Triage (enrichment) |
| `risk-score.risk-score-latest-*` | Attack Discovery (entity risk scoring) |

### Kibana feature privileges (9.4+)

| Feature | Privilege | Why |
|---|---|---|
| Security > Security | Read | Base access gate |
| Security > Cases | Read | View cases |
| Security > Timeline | Read | View timelines |
| Security > Notes | Read | View notes |
| Security > Rules and Exceptions | Read | View rules |
| Security > Alerts | Read | View alerts |
| Security > Elastic AI Assistant | None | Not available in read-only |
| Security > Attack discovery | None | Not available in read-only |
| Management > Actions and Connectors | None | Not available in read-only |

### Dev Tools: Create the role

```
PUT /_security/role/mcp_app_readonly
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": [
        ".alerts-security.alerts-<space-id>",
        ".alerts-security.attack.discovery.alerts-<space-id>",
        ".adhoc.alerts-security.attack.discovery.alerts-<space-id>",
        "logs-*",
        "risk-score.risk-score-latest-*"
      ],
      "privileges": ["read"]
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
        "feature_securitySolutionRulesV4.read",
        "feature_securitySolutionAlertsV1.read"
      ],
      "resources": ["space:<space-id>"]
    }
  ]
}
```

### Create an API key scoped to this role

```
POST /_security/api_key
{
  "name": "mcp-app-readonly",
  "role_descriptors": {
    "mcp_app_readonly": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": [
            ".alerts-security.alerts-<space-id>",
            ".alerts-security.attack.discovery.alerts-<space-id>",
            ".adhoc.alerts-security.attack.discovery.alerts-<space-id>",
            "logs-*",
            "risk-score.risk-score-latest-*"
          ],
          "privileges": ["read"]
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
            "feature_securitySolutionRulesV4.read",
            "feature_securitySolutionAlertsV1.read"
          ],
          "resources": ["space:default"]
        }
      ]
    }
  }
}
```

---

## Troubleshooting

### 401 Unauthorized

- API key is invalid, expired, or malformed
- Verify with: `curl -s -H "Authorization: ApiKey <your-key>" <ELASTICSEARCH_URL>/_security/_authenticate`

### 403 Forbidden on Kibana APIs

- Missing Kibana feature privileges — the role needs application privileges on `kibana-.kibana`
- Check which features are missing: the 403 response body usually names the required privilege
- Common cause: forgetting to grant privileges in the correct Kibana space

### Attack Discovery returns 403

- Requires **all three**: Elastic AI Assistant (All), Attack discovery (All), and Actions and Connectors (All)
- Also requires Rules and Exceptions + Alerts feature privileges as prerequisites

### Space ID mismatch

- Index patterns use the Kibana space ID (e.g., `.alerts-security.alerts-default`)
- If using a non-default space, update all index patterns and the `resources` field in the role definition
- The app currently targets the `default` space

### "No alerts found" but alerts exist in Kibana

- The API key's index privileges may not cover the alert index for your space
- Check the space ID in the index pattern matches your Kibana space

---

## Appendix: Per-Tool Privilege Breakdown

Use this appendix to build custom roles that enable only specific tools.

### Alert Triage

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| Search alerts | `monitor` | `read` on `.alerts-security.alerts-<space-id>` | Security (Read), Alerts (Read) |
| View alert context | `monitor` | `read` on `.alerts-security.alerts-<space-id>`, `logs-endpoint.events.process-*`, `logs-endpoint.events.network-*` | Security (Read), Alerts (Read) |
| Acknowledge alerts | `monitor` | `read`, `write` on `.alerts-security.alerts-<space-id>` | Security (All), Alerts (All) |

### Attack Discovery

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| View discoveries | `monitor` | `read` on `.alerts-security.attack.discovery.alerts-<space-id>`, `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Security (Read), Attack discovery (Read) |
| Assess confidence | `monitor` | `read` on `.alerts-security.alerts-<space-id>`, `risk-score.risk-score-latest-*` | Security (Read), Attack discovery (Read) |
| Generate discoveries | `monitor` | `read` on `.alerts-security.alerts-<space-id>` | Security (All), Rules and Exceptions (All), Alerts (All), Elastic AI Assistant (All), Attack discovery (All), Actions and Connectors (All) |
| Acknowledge discoveries | `monitor` | `read`, `write` on `.alerts-security.attack.discovery.alerts-<space-id>`, `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Security (All), Attack discovery (All) |

### Case Management

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| List/view cases | — | — | Security (Read), Cases (Read) |
| View case alerts | — | `read` on `.alerts-security.alerts-<space-id>` | Security (Read), Cases (Read), Alerts (Read) |
| Create/update cases | — | — | Security (All), Cases (All) |
| Add comments | — | — | Security (All), Cases (All) |
| Attach alerts | — | — | Security (All), Cases (All) |

### Detection Rules

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| List/view rules | — | — | Security (Read), Rules and Exceptions (Read) |
| Validate queries | — | `read` on `.alerts-security.alerts-<space-id>` | Security (Read) |
| Noisy rules report | — | `read` on `.alerts-security.alerts-<space-id>` | Security (Read), Rules and Exceptions (Read), Alerts (Read) |
| Create/patch/delete rules | — | — | Security (All), Rules and Exceptions (All) |
| Toggle rules | — | — | Security (All), Rules and Exceptions (All) |
| Add exceptions | — | — | Security (All), Rules and Exceptions (All) |

### Threat Hunt

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| ES\|QL queries | `monitor` | `read` on target indices (e.g., `logs-*`) | Security (Read) |
| List indices | `monitor` | `read` on target indices | Security (Read) |
| Field mappings | `monitor` | `read` on target indices | Security (Read) |
| Entity detail | `monitor` | `read` on `logs-endpoint.events.process-*`, `logs-endpoint.events.network-*`, `.alerts-security.alerts-<space-id>` | Security (Read), Alerts (Read) |

### Sample Data

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| Check existing data | `monitor` | `read` on `.alerts-security.alerts-<space-id>`, `logs-*` | Security (Read) |
| Generate sample data | `monitor` | `read`, `write` on `logs-*` | Security (All), Rules and Exceptions (All) |
| Cleanup sample data | `monitor` | `read`, `write` on `logs-*`, `.alerts-security.alerts-<space-id>` | Security (All), Rules and Exceptions (All), Alerts (All) |

---

## Notes

### Legacy `.siem-signals-<space-id>` index

If your cluster was upgraded from Elastic Security 8.0 or earlier, detection alerts may still exist in `.siem-signals-<space-id>` instead of `.alerts-security.alerts-<space-id>`. Add `read` (and `write` for acknowledgment) privileges on `.siem-signals-<space-id>` if you need to access these legacy alerts.

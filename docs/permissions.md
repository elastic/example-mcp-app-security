# Minimum Required Permissions

This guide defines the least-privilege roles for the Elastic Security MCP app on **stateful (self-managed and Elastic Cloud Hosted) deployments**. Two paths:

- **[Quickstart](#quickstart--built-in-roles)** — assign a built-in Kibana role plus a small index-privileges add-on. Recommended for most users.
- **[Advanced — Custom roles](#advanced--custom-roles)** — fully scripted role JSON. Use when you need to provision via API/IaC, or want finer-grained control than the built-ins offer.

> **Space ID:** Kibana index patterns include a `<space-id>` segment (e.g., `.alerts-security.alerts-<space-id>`). For most deployments this is `default`. Replace `<space-id>` with your actual space ID throughout this guide. The app currently targets the `default` space.

> **Serverless:** This guide targets stateful deployments. Serverless projects ship a different set of built-in roles (`t1_analyst`, `soc_manager`, etc.) and aren't covered here yet.

---

## Quickstart — Built-in roles

Two pre-built Kibana roles cover the entire Kibana feature surface the MCP app needs (Security, Cases, Timeline, Notes, Rules, Alerts, AI Assistant, Attack Discovery, Actions and Connectors). You only need to add a small block of **Elasticsearch index privileges** on top — Kibana feature privileges require no toggling.

### Full-featured access

**1. Create a companion role for index privileges**

Stack Management → Roles → **Create role** → name it `mcp_app_indexes_full`, grant **Cluster privilege** `monitor`, and grant the following **Index privileges**:

| Index pattern | Privileges |
|---|---|
| `.alerts-security.alerts-<space-id>` | `read`, `write`, `monitor` |
| `.alerts-security.attack.discovery.alerts-<space-id>` | `read`, `write`, `monitor` |
| `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | `read`, `write`, `monitor` |
| `.internal.alerts-security.alerts-<space-id>-*` | `read`, `write`, `monitor` |
| `.internal.alerts-security.attack.discovery.alerts-<space-id>-*` | `read`, `write`, `monitor` |
| `.internal.adhoc.alerts-security.attack.discovery.alerts-<space-id>-*` | `read`, `write`, `monitor` |
| `logs-*` | `read`, `write`, `monitor` |
| `risk-score.risk-score-latest-*` | `read`, `monitor` |

> Why cluster `monitor` *and* index-level `monitor`: `_cat/indices/<pattern>` (used by Threat Hunt to list indices) needs both. The cluster-level grant lets the user enumerate indices at all; the index-level grant lets `_cat/indices` and `_mapping` actually return data for those patterns. Neither `editor` nor `viewer` grants cluster `monitor`, so it has to come from this companion role.

No Kibana-feature or application privileges in this companion role — those come from `editor`.

**2. Assign roles to a user**

Stack Management → Users → **Create user** (or edit an existing one) → assign **both** roles:

- `editor` (built-in) — covers all Kibana features for read/write Security workflows.
- `mcp_app_indexes_full` (the companion role created above).

**3. Create an API key for that user**

Sign in as the new user, then **Stack Management → API keys → Create API key**. Kibana mints the key inheriting the user's combined privileges from both roles. The "Encoded" value is what you set as `ELASTICSEARCH_API_KEY` in the MCP app config.

### Read-only access

**1. Create a companion role for index privileges**

Stack Management → Roles → **Create role** → name it `mcp_app_indexes_readonly`, grant **Cluster privilege** `monitor`, and grant the following **Index privileges**:

| Index pattern | Privileges |
|---|---|
| `.alerts-security.alerts-<space-id>` | `read`, `monitor` |
| `.alerts-security.attack.discovery.alerts-<space-id>` | `read`, `monitor` |
| `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | `read`, `monitor` |
| `.internal.alerts-security.alerts-<space-id>-*` | `read`, `monitor` |
| `.internal.alerts-security.attack.discovery.alerts-<space-id>-*` | `read`, `monitor` |
| `.internal.adhoc.alerts-security.attack.discovery.alerts-<space-id>-*` | `read`, `monitor` |
| `logs-*` | `read`, `monitor` |
| `risk-score.risk-score-latest-*` | `read`, `monitor` |

**2. Assign roles to a user**

Assign **both** `viewer` (built-in) and `mcp_app_indexes_readonly` to the user.

**3. Create an API key**

Same as above — sign in as the user and create the key from Stack Management → API keys.

### What the built-ins cover

| Surface | `editor` | `viewer` |
|---|---|---|
| All Kibana features (SIEM, Cases, Timeline, Notes, Rules, Alerts, AI Assistant, Attack Discovery, Actions/Connectors) | All | Read |
| Alert acknowledgment, case CRUD, rule CRUD | Yes (via Kibana APIs) | No |
| Sample-data generation | Needs companion `write` on `logs-*` (covered above) | Disabled |
| Threat Hunt index listing | Needs companion `monitor` on target indices (covered above) | Same |

The built-ins eliminate the need to specify per-feature privileges like `feature_siemV5.all` or `feature_securitySolutionRulesV4.all`. Those names change between minor versions; the built-ins absorb the churn.

---

## Troubleshooting

### 401 Unauthorized

- API key is invalid, expired, or malformed
- Verify with: `curl -s -H "Authorization: ApiKey <your-key>" <ELASTICSEARCH_URL>/_security/_authenticate`

### 403 Forbidden on Kibana APIs

- Missing Kibana feature privileges — the role needs application privileges on `kibana-.kibana`. The Quickstart's `editor`/`viewer` covers these by default.
- Check which features are missing: the 403 response body usually names the required privilege.
- Common cause: forgetting to grant privileges in the correct Kibana space.

### 403 on Threat Hunt → "list indices"

- The companion role is missing index-level `monitor` on the target index pattern.
- `_cat/indices/<pattern>` requires index-level `monitor`; cluster-level `monitor` alone is not sufficient.

### Attack Discovery returns 403

- Built-in `editor` covers the AI Assistant, Attack discovery, and Actions/Connectors feature privileges. If you scoped the key narrower than `editor`, restore those grants — Attack Discovery requires **all three** plus Rules and Alerts.

### Sample-data generation returns 403

- Companion role is missing `write` on `logs-*` and the alert backing indices. The `editor` built-in does **not** grant raw index `write`; it must come from the companion role.

### Space ID mismatch

- Index patterns use the Kibana space ID (e.g., `.alerts-security.alerts-default`)
- If using a non-default space, update all index patterns in the companion role
- The app currently targets the `default` space

### "No alerts found" but alerts exist in Kibana

- The companion role's index privileges may not cover the alert index for your space
- Check the space ID in the index pattern matches your Kibana space

---

## Advanced — Custom roles

Use this path when:

- You provision roles via API, Terraform, or other IaC and want a single self-contained role definition.
- You need finer-grained restriction than the built-ins offer (e.g. Cases-only, no Threat Hunt).
- Your users' built-in role assignments are managed elsewhere and you can't add `editor`/`viewer` to them.

Each role below is a single self-contained definition — no companion role required.

### Full-Featured Role

#### Cluster privileges

| Privilege | Why |
|---|---|
| `monitor` | `_cat/indices` for Threat Hunt, AI Assistant prerequisite |

#### Index privileges

**System / alert indices** (`read`, `write`, `monitor`):

| Index pattern | Used by |
|---|---|
| `.alerts-security.alerts-<space-id>` | Alert Triage, Attack Discovery, Detection Rules, Case Management, Sample Data cleanup |
| `.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery |
| `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery (ad-hoc generated) |
| `.internal.alerts-security.alerts-<space-id>-*` | Backing indices for the alert data stream |
| `.internal.alerts-security.attack.discovery.alerts-<space-id>-*` | Backing indices for the attack-discovery data stream |
| `.internal.adhoc.alerts-security.attack.discovery.alerts-<space-id>-*` | Backing indices for the ad-hoc attack-discovery data stream |

**Data indices** (`read`, `write`, `monitor`):

| Index pattern | Used by |
|---|---|
| `logs-*` | Threat Hunt, Alert Triage (enrichment), Sample Data (write + cleanup) |
| `risk-score.risk-score-latest-*` | Attack Discovery (entity risk scoring) |

#### Kibana feature privileges

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

#### Dev Tools: Create the role

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
        ".internal.alerts-security.alerts-<space-id>-*",
        ".internal.alerts-security.attack.discovery.alerts-<space-id>-*",
        ".internal.adhoc.alerts-security.attack.discovery.alerts-<space-id>-*",
        "logs-*",
        "risk-score.risk-score-latest-*"
      ],
      "privileges": ["read", "write", "monitor"]
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

#### Create an API key for this role

Two-step recipe — assign the role to a user, then mint an API key that inherits the user's privileges:

```
PUT /_security/user/mcp_app_user
{
  "password": "<choose-a-strong-password>",
  "roles": ["mcp_app_full"]
}
```

Then, **authenticated as `mcp_app_user`** (or via `POST /_security/api_key/grant` as an admin):

```
POST /_security/api_key
{
  "name": "mcp-app-full"
}
```

The response includes an `encoded` field — use that as your `ELASTICSEARCH_API_KEY`. No `role_descriptors` needed: the key inherits the user's role privileges directly.

### Read-Only Role

A strict read-only role: view everything, change nothing.

> Need to acknowledge alerts or create cases? Use the full-featured role, or build a custom role using the [per-tool privilege breakdown](#appendix-per-tool-privilege-breakdown).

#### Cluster privileges

| Privilege | Why |
|---|---|
| `monitor` | `_cat/indices` for Threat Hunt |

#### Index privileges

**All index patterns** (`read`, `monitor`):

| Index pattern | Used by |
|---|---|
| `.alerts-security.alerts-<space-id>` | Alert Triage, Detection Rules, Case viewing |
| `.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery viewing |
| `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Attack Discovery viewing |
| `.internal.alerts-security.alerts-<space-id>-*` | Backing indices for the alert data stream |
| `.internal.alerts-security.attack.discovery.alerts-<space-id>-*` | Backing indices for the attack-discovery data stream |
| `.internal.adhoc.alerts-security.attack.discovery.alerts-<space-id>-*` | Backing indices for the ad-hoc attack-discovery data stream |
| `logs-*` | Threat Hunt, Alert Triage (enrichment) |
| `risk-score.risk-score-latest-*` | Attack Discovery (entity risk scoring) |

#### Kibana feature privileges (9.4+)

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
| Management > Actions and Connectors | Read | List configured AI connectors (no execute) |

#### Dev Tools: Create the role

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
        ".internal.alerts-security.alerts-<space-id>-*",
        ".internal.alerts-security.attack.discovery.alerts-<space-id>-*",
        ".internal.adhoc.alerts-security.attack.discovery.alerts-<space-id>-*",
        "logs-*",
        "risk-score.risk-score-latest-*"
      ],
      "privileges": ["read", "monitor"]
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
        "feature_securitySolutionAlertsV1.read",
        "feature_actions.read"
      ],
      "resources": ["space:<space-id>"]
    }
  ]
}
```

#### Create an API key for this role

```
PUT /_security/user/mcp_app_readonly_user
{
  "password": "<choose-a-strong-password>",
  "roles": ["mcp_app_readonly"]
}
```

Then, authenticated as the new user:

```
POST /_security/api_key
{
  "name": "mcp-app-readonly"
}
```

---

## Appendix: Per-Tool Privilege Breakdown

Use this appendix to build custom roles that enable only specific tools.

### Alert Triage

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| Search alerts | `monitor` | `read` on `.alerts-security.alerts-<space-id>` | Security (Read), Alerts (Read) |
| View alert context | `monitor` | `read` on `.alerts-security.alerts-<space-id>`, `logs-endpoint.events.process-*`, `logs-endpoint.events.network-*` | Security (Read), Alerts (Read) |
| Acknowledge alerts | `monitor` | `read`, `write` on `.alerts-security.alerts-<space-id>` and `.internal.alerts-security.alerts-<space-id>-*` | Security (All), Alerts (All) |

### Attack Discovery

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| View discoveries | `monitor` | `read` on `.alerts-security.attack.discovery.alerts-<space-id>`, `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` | Security (Read), Attack discovery (Read) |
| Assess confidence | `monitor` | `read` on `.alerts-security.alerts-<space-id>`, `risk-score.risk-score-latest-*` | Security (Read), Attack discovery (Read) |
| Generate discoveries | `monitor` | `read` on `.alerts-security.alerts-<space-id>` | Security (All), Rules and Exceptions (All), Alerts (All), Elastic AI Assistant (All), Attack discovery (All), Actions and Connectors (All) |
| Acknowledge discoveries | `monitor` | `read`, `write` on `.alerts-security.attack.discovery.alerts-<space-id>`, `.adhoc.alerts-security.attack.discovery.alerts-<space-id>` and the matching `.internal.*-*` backing-index patterns | Security (All), Attack discovery (All) |

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
| List indices | `monitor` | `read`, `monitor` on target indices | Security (Read) |
| Field mappings | `monitor` | `read`, `monitor` on target indices | Security (Read) |
| Entity detail | `monitor` | `read` on `logs-endpoint.events.process-*`, `logs-endpoint.events.network-*`, `.alerts-security.alerts-<space-id>` | Security (Read), Alerts (Read) |

### Sample Data

| Operation | Cluster | Index privileges | Kibana features |
|---|---|---|---|
| Check existing data | `monitor` | `read` on `.alerts-security.alerts-<space-id>`, `logs-*` | Security (Read) |
| Generate sample data | `monitor` | `read`, `write` on `logs-*`, `.alerts-security.alerts-<space-id>` and `.internal.alerts-security.alerts-<space-id>-*` | Security (All), Rules and Exceptions (All), Alerts (All) |
| Cleanup sample data | `monitor` | `read`, `write` on `logs-*`, `.alerts-security.alerts-<space-id>` and `.internal.alerts-security.alerts-<space-id>-*` | Security (All), Rules and Exceptions (All), Alerts (All) |

---

## Notes

### Legacy `.siem-signals-<space-id>` index

If your cluster was upgraded from Elastic Security 8.0 or earlier, detection alerts may still exist in `.siem-signals-<space-id>` instead of `.alerts-security.alerts-<space-id>`. Add `read` (and `write` for acknowledgment) privileges on `.siem-signals-<space-id>` if you need to access these legacy alerts.

# Telemetry

The Elastic Security MCP App emits a small set of anonymised usage events
via [`@elastic/ebt`](https://www.npmjs.com/package/@elastic/ebt) so the
team can see which views and tools are being used. Events ship to
`telemetry.elastic.co` and are subject to the same opt-in the user
controls in Kibana — the app never reports anything when Kibana
telemetry is disabled.

## Opt-in source of truth

On MCP server start the app fetches the user's telemetry config from the
default-cluster Kibana:

```
GET /api/telemetry/v2/config
```

The response's `optIn` field maps to the analytics client's shipping
state:

| Kibana `optIn`   | App behaviour                       |
|------------------|-------------------------------------|
| `true`           | Events ship to `telemetry.elastic.co` |
| `false`          | Events queued in-memory, then dropped |
| `null`           | Treated as opted-out                |
| Fetch error      | Treated as opted-out (fail-closed)  |

The `optIn` is read once at startup; there is no polling. Restart the
MCP server (or your MCP host) after flipping the Kibana setting for the
change to take effect.

## What gets collected

### `mcp_tool_called` (server-side)

Emitted every time an MCP tool handler returns or throws. Wrapped
around every model-facing tool and every app-only tool _except_
`report-analytics-event` (which would otherwise duplicate the
`view_rendered` traffic).

| Field         | Type    | Notes                                                  |
|---------------|---------|--------------------------------------------------------|
| `tool_id`     | keyword | One of the values listed under "Allowed tool ids" below |
| `duration_ms` | long    | Wall-clock duration of the handler, in milliseconds    |
| `success`     | boolean | `true` if the handler resolved, `false` if it threw    |

### `view_rendered` (client-side)

Emitted once per mount of each top-level React view, via the app-only
`report-analytics-event` MCP tool.

| Field     | Type    | Allowed values (closed enum)                                                                                |
|-----------|---------|-------------------------------------------------------------------------------------------------------------|
| `view_id` | keyword | `alert-triage`, `attack-discovery`, `case-management`, `detection-rules`, `sample-data`, `threat-hunt`      |

## Allowed `tool_id` values

`tool_id` is bound to the registered MCP tool name, so renames here are
schema-impacting events for downstream dashboards. The current set:

```
acknowledge-alert
acknowledge-alerts-bulk
acknowledge-discoveries
add-case-comment
approve-discoveries
assess-discovery-confidence
attach-alert-to-case
check-existing-sample-data
cleanup-sample-data
create-case
create-rule
create-rules-for-scenario
enrich-discovery
emulation-run
execute-esql
find-rules
generate-attack-discovery
generate-sample-data
generate-scenario
get-alert-context
get-case
get-case-alerts
get-case-comments
get-entity-detail
get-generation-status
get-mapping
get-rule
get-user-profile
investigate-entity
list-ai-connectors
list-cases
list-indices
manage-cases
manage-exceptions
manage-rules
noisy-rules
patch-rule
poll-alerts
poll-discoveries
threat-hunt
toggle-rule
triage-alerts
triage-attack-discoveries
unacknowledge-alert
update-case
validate-query
```

Add new tools by registering them with `registerTrackedAppTool` — they
will start appearing automatically once shipped.

## Context attached to every event

The Elastic V3 shipper enriches each event with a small context block
derived from the **default** cluster:

| Field             | Source                              | Notes                                          |
|-------------------|-------------------------------------|------------------------------------------------|
| `cluster_uuid`    | Elasticsearch `GET /`               | Required by the V3 shipper; events do not ship without it |
| `cluster_version` | Elasticsearch `GET /` `version.number` | Stack version                              |
| `license_id`      | Elasticsearch `GET /_license`       | Optional                                       |
| `license_status`  | Elasticsearch `GET /_license`       | Optional                                       |
| `license_type`    | Elasticsearch `GET /_license`       | Optional                                       |
| `mcp_app_version` | `package.json` `version`            | Version of the MCP App that emitted the event  |

`cluster_name` is deliberately **not** collected. It's user-controlled
and frequently contains company / environment identifiers, so shipping
it would undermine the "anonymised" framing of this feed.

### Segmentation granularity

There is no `install_id` — two MCP App installs against the same Elastic
cluster will share `cluster_uuid` and are not distinguishable in the
telemetry stream. This is fine for v1; if per-install segmentation
becomes important later we can stamp a random UUID into the credential
file on first run and add it as a context field.

## What does **not** get collected

The schemas above are closed — no free-form text, no PII, no Kibana
user identifiers, no alert / case / rule bodies, no ES|QL queries.
Adding a new field requires:

1. Extending `McpToolCalledEvent` / `ViewRenderedEvent` in
   `src/elastic/analytics/events.ts` (and its EBT schema sibling).
2. Adding the field to the registered context provider or event
   definition.
3. Updating this document.

The `report-analytics-event` MCP tool that the frontend uses to forward
client-side events accepts a strict Zod schema (`eventType: z.literal`,
`viewId: z.enum`) so a malicious or buggy view cannot smuggle free-form
text into the pipeline.

## Opting out

End-users have one knob: the **Kibana** telemetry setting. The MCP
App mirrors it; flipping it off in Kibana stops the MCP App from
shipping any events. Restart the MCP host after flipping the setting.

### Developer escape hatches

| Environment variable          | Effect                                                                                                       |
|-------------------------------|--------------------------------------------------------------------------------------------------------------|
| `MCP_APP_TELEMETRY_ENV=staging` | Ships events to `telemetry-staging.elastic.co` instead of production. Useful for local dev / dashboard work. |
| `NODE_ENV=production`         | Currently only affects EBT's internal `isDev` flag (logging verbosity). Does **not** disable shipping.       |

The MCP App does not provide an "always off regardless of Kibana"
override beyond unsetting the user's Kibana opt-in. If you need that,
turn off Kibana telemetry on your dev cluster — the fail-closed
behaviour does the rest.

## Bundle-size impact

Adding `@elastic/ebt@^1.4.1` (which transitively pulls `rxjs`,
`fp-ts`, `io-ts`, `moment`, `js-sha256`, `lodash.get`, `lodash.has`,
`node-fetch@2`, and `@babel/runtime`) increases the bundled
`dist/main.bundle.mjs` by roughly **+560 KB raw / +113 KB gzipped**
(~15% raw, ~17% gzipped) on a fresh measurement. This is a one-time
download for `.mcpb` installs; the bundle is loaded into the MCP host
once and reused across sessions.

`node-fetch@2` is redundant on Node 22 (native `fetch`) but EBT pulls
it unconditionally; tree-shaking it out would require a fork of
`@elastic/ebt`. Acceptable for now.

## Where things live in the codebase

```
src/elastic/analytics/
  analytics-client.ts          - AnalyticsClient interface (what the rest of the app sees)
  create-analytics-client.ts   - Factory: registers ElasticV3ServerShipper + EBT event types + context providers
  context-loader.ts            - One-shot GET / + GET /_license on startup
  events.ts                    - Event type IDs and Zod-typed payload schemas
  index.ts                     - Public module surface

src/elastic/client/telemetryConfigClient.ts
  Wraps GET /api/telemetry/v2/config on the default-cluster Kibana

src/elastic/service/telemetryService.ts
  Fetches the telemetry config and mirrors optIn → analytics.setOptIn

src/tools/tracked-app-tool.ts
  Drop-in replacement for `registerAppTool` that emits `mcp_tool_called`

src/tools/analytics.ts
  Registers the app-only `report-analytics-event` MCP tool

src/shared/hooks/McpAppProvider.tsx, useMcpApp.ts, useAnalytics.ts
  React context + hooks: provider owns the McpApp; useAnalytics reads it

src/shared/analytics-events.ts
  Single source of truth for the view-id enum, imported by both server and views
```

---
name: automatic-migration
description: >
  Migrate detection rules from Splunk (or other SIEMs) to Elastic Security. Use for
  "migrate my Splunk rules", "import SPL", "onboard from Splunk", "SIEM migration",
  "convert detection rules", "translate SPL to EQL", or any request to move security
  rules from a third-party platform into Elastic. Vendor support: Splunk (active),
  QRadar / Sentinel-One (coming soon).
---

# Automatic Migration

Migrate third-party SIEM detection rules into Elastic Security using the `elastic-security`
MCP connector. Call `migrate-rules` ONCE — it opens an interactive workbench that guides
the SOC engineer through every stage of the migration. Do NOT attempt to drive the process
step-by-step through prose or individual tool calls; the workbench handles all state
transitions internally.

## Tools

| Tool | Caller | Purpose |
|------|--------|---------|
| `migrate-rules` | Model | **Entry point.** Opens the interactive migration workbench. No parameters required. |
| `list-migrations` | Workbench | List all existing SIEM migrations |
| `get-migration` | Workbench | Get status and rule counts for a specific migration |
| `get-translated-rules` | Workbench | Fetch translated rules (paginated, filterable) |
| `start-translation` | Workbench | Trigger AI translation of uploaded rules |
| `stop-translation` | Workbench | Cancel an in-progress translation |
| `update-translated-rule` | Workbench | Save manual edits to a translated rule |
| `get-resources` | Workbench | List macro/lookup resources referenced by translated rules |
| `upsert-resource` | Workbench | Create or update a macro or lookup definition |
| `install-rules` | Workbench | Install translated rules into Elastic Security (installed as disabled) |
| `get-stats` | Workbench | Get translation progress counts for a migration |

Only `migrate-rules` is model-facing. All other tools are called by the workbench via its
back-channel. Do not call them directly in conversation.

## Workbench Lifecycle

| Stage | What the user does | Completion signal |
|-------|--------------------|-------------------|
| **vendor-select** | Picks the source SIEM (Splunk active; QRadar / Sentinel-One coming soon) | Vendor button clicked |
| **upload** | Drops a JSON export file, uses the file picker, or pastes a rules array | "Upload & start translation" clicked |
| **translating** | Waits while the AI translator processes rules; live progress bar | Migration status reaches `finished` or `error` |
| **review** | Reviews each rule's three-column diff (original SPL / generated / editable) | "Install N rules" clicked |
| **fix-rule-drawer** | Edits key fields of a single rule (name, query, language, severity, risk score) via structured form; "Re-validate" marks it `partial`, "Save" uses the selected result | Drawer closed |
| **fix-resources-drawer** | Provides definitions for unresolved macros and lookups; each row has an individual Save button calling `upsert-resource` | "Done" in the drawer |
| **install** | Confirms installation of all translatable rules; "Back to review" is available | "Confirm install" clicked |
| **done** | Views the installed / failed summary | — |

## Correction Strategy

If the user wants to revisit or undo a step:

- **Start over at any step**: the "Start over" button in the header resets to vendor-select.
- **Back from install confirmation**: click "Back to review" to return without installing.
- **Re-edit a specific rule**: re-open the rule drawer from the review list and save again;
  each save calls `update-translated-rule` and refreshes the list in-place.
- **Re-edit a resource**: re-open the resources drawer; each per-row "Save" calls
  `upsert-resource` and re-fetches the resources list without closing the drawer.
- **Restart translation**: use "Start over", re-upload the rules, then re-trigger translation.

The workbench never permanently deletes data. Translation results and rule edits are persisted
in Kibana; re-opening the workbench via `migrate-rules` will show all prior migrations.

## Common Gotchas

**Vendor not supported.** QRadar and Sentinel-One show as "Coming soon" — their vendor-select
buttons are disabled. If the user asks to migrate from a non-Splunk platform, explain that
only Splunk is currently supported and suggest they check the Elastic roadmap for updates.

**Calling app-only tools directly.** Do not call `start-translation`, `get-translated-rules`,
`install-rules`, or any other app-only tool manually. They are wired to the workbench
back-channel and will return raw JSON with no useful context in a prose conversation. Always
call `migrate-rules` once and let the workbench drive everything else.

**Upload format.** The upload step expects a JSON array of Splunk rule objects as exported from
the Splunk Enterprise Security Rules page. Each object must include a `search` field containing
the raw SPL query. Other formats (YAML, CSV, Splunk `.conf` files) are not supported and will
fail silently.

**Partial translations.** Rules marked `partial` were AI-translated but may need tuning before
they match the customer's data. They can be installed, but Elastic Security will show them as
disabled; the SOC engineer should review and enable them manually. Rules marked `untranslatable`
are skipped during installation entirely.

**Macro and lookup references.** Splunk rules that reference custom macros or lookups will
translate with placeholder references. The fix-resources-drawer lists all detected unresolved
references and auto-expands them. Fill in each definition before installing — installed rules
that reference undefined macros will not fire correctly.

**Large rule sets.** Translation is asynchronous. For large exports (hundreds of rules), the
translating stage may run for several minutes. The progress bar polls every 3 seconds
automatically. Do not suggest calling `stop-translation` unless the user explicitly wants to
cancel and discard in-progress results.

**Re-opening an existing migration.** Calling `migrate-rules` when one or more migrations
already exist will show them in the response JSON. The workbench starts at vendor-select each
time — there is no "resume" flow yet. To continue working on an existing migration, the user
must navigate through the workbench stages again; prior translations are preserved on the
server and will reappear in the review step after re-triggering translation.

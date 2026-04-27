# Permissions Test Tooling

Verifies that the role definitions documented in [`docs/permissions.md`](../../docs/permissions.md) actually work end-to-end against a real Elasticsearch + Kibana cluster. Provisions both documented roles, creates scoped API keys, and exercises every documented operation through the existing `src/elastic/*` business-logic modules.

## Quick Start

```bash
# Make sure .env has ELASTICSEARCH_URL, ELASTICSEARCH_API_KEY, KIBANA_URL
# (the API key must have manage_security plus enough privileges to seed sample data)

npm run test:permissions
```

Exit code is `0` if every check passes (or is skipped); `1` otherwise.

## Flags

| Flag | Description |
|---|---|
| `--role full\|readonly\|both` | Which role(s) to test (default: `both`). |
| `--cleanup-stale` | Delete leftover `mcp-app-test-*` roles and API keys before running. Useful after a crashed run. |
| `--no-cleanup` | Skip cleanup at the end and print the provisioned API keys so you can re-use them for manual debugging. |
| `--verbose`, `-v` | Print fixtures, stale-cleanup actions, and other debug info. |
| `-h`, `--help` | Show help. |

Pass flags via `--`, e.g. `npm run test:permissions -- --role readonly --verbose`.

## What it does

1. **Pre-flight.** Loads admin credentials from `.env`. Calls `checkExistingData()`; if the cluster has zero security alerts, calls `generateSampleData({ count: 50 })` to seed.
2. **Capture fixtures.** Picks one alert, one case (creates one if none exist), and the first detection rule.
3. **For each role (`full`, then `readonly`):**
   - Creates a role `mcp-app-test-<role>-<suffix>` and an API key scoped to it.
   - **Layer A** — calls `POST /_security/user/_has_privileges` as the scoped key, asserting that every privilege listed in the role descriptor is granted.
   - **Layer B** — exercises one or more operations per group (alerts, cases, rules, attack-discovery, threat-hunt, sample-data) using the actual `src/elastic/*` functions. Reads must succeed for both roles. Writes must succeed for `full` and 403 for `readonly`.
4. **Report** — prints per-role results grouped by operation group. Symbols: `✓` pass, `✗` fail, `→` skipped.
5. **Cleanup** — always (in a `finally` block, and on `SIGINT`): invalidates API keys and deletes roles created by the run.

Created cases / rules / sample documents are tagged `mcp-app-test` and are **not** automatically deleted. If they accumulate, clean them up via Kibana or with a tag-scoped delete.

## Output Interpretation

Each line in the report looks like:

```
✓ acknowledgeAlert (expect 403) — denied (403/401)
✗ createCase (expect 403) — expected 403 but call succeeded
→ patchRule (expect 403) — no fixture available for this check
```

- `pass` (`✓`) — outcome matched the expectation (call succeeded when expected `ok`, or call returned 403/401 when expected `403`).
- `fail` (`✗`) — outcome diverged from the expectation. The detail explains what happened.
- `skipped` (`→`) — the cluster did not have a fixture for this op (e.g. no rule to patch). Skipped checks do **not** affect the exit code.

The summary line lists totals: `Summary: N passed, M failed, K skipped`.

## Troubleshooting

**Read-only writes return `ok` instead of `403` (e.g. `expected 403 but call succeeded`).**
The read-only role is over-privileged. Compare `roles.ts` to the read-only role in [`docs/permissions.md`](../../docs/permissions.md) — usually a stale `"write"` snuck into `indices.privileges`, or an `*.all` Kibana feature privilege replaced an `*.read` one.

**Full-featured writes return `403`.**
A privilege documented in the full role is missing from `roles.ts`. Diff against the spec.

**Layer A reports `missing privileges: ...`.**
The role descriptor sent in the `PUT /_security/role` body doesn't include the listed privileges, or Elasticsearch rejected one of them (typo / removed feature). Check that the Kibana feature names match your stack version. The defaults target 9.4+ — see the version-specific tables in `docs/permissions.md`.

**`Fatal error: ELASTICSEARCH_URL is required.`**
`.env` isn't loading or doesn't have all three of `ELASTICSEARCH_URL`, `ELASTICSEARCH_API_KEY`, `KIBANA_URL`. The script reads them via `dotenv/config`.

**`Seeding completed but no security alerts were created.`**
`generateSampleData` ran but didn't end up writing alerts. Usually means the admin key lacks `write` on `.alerts-security.alerts-default`. Use a key with at least the privileges in the full role.

**Leftover `mcp-app-test-*` roles or API keys.**
A previous run was killed before cleanup. Re-run with `--cleanup-stale` to wipe them, or delete manually via Kibana > Stack Management.

## Architecture

```
scripts/test-permissions/
├── roles.ts          # Role descriptors + operation check matrix
├── elastic-admin.ts  # PUT/DELETE role, POST/DELETE api_key, _has_privileges probe
├── runner.ts         # Orchestrator: provision → seed → test → report → cleanup
└── README.md         # This file
```

The runner reuses business logic from `src/elastic/*` and swaps the API key on the singleton config (`setConfig`) between admin and each scoped role. This forces sequential per-role execution; that's fine at this scale.

## Updating the Test Matrix

When you add or remove an operation from `src/elastic/*`, also update `operationChecks` in [`roles.ts`](./roles.ts):

- Add an entry naming the function and its group.
- Set `expect.full` to `"ok"` and `expect.readonly` to either `"ok"` (read) or `"403"` (write).
- If the call needs a fixture that may not exist, add `skipUnless` and gate it on the fixture.
- If the function silences errors internally (e.g. wraps each ES call in `try { ... } catch {}`), it's not testable here — either refactor the function to surface 403s or pick a different operation that hits the same privilege.

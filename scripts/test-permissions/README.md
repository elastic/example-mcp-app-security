# Permissions Test Tooling

Verifies that the role definitions documented in [`docs/permissions.md`](../../docs/permissions.md) actually work end-to-end against a real Elasticsearch + Kibana cluster. Provisions both documented roles, creates scoped API keys, and exercises every documented operation through the existing `src/elastic/*` business-logic modules.

Supports both **stateful** (default) and **serverless** deployment modes — see [Serverless mode](#serverless-mode) below.

## Quick Start

```bash
# Make sure .env has ELASTICSEARCH_URL, KIBANA_URL, ELASTIC_PASSWORD
# (and ELASTIC_USERNAME if not the default "elastic").
# The runner authenticates as that user via Basic auth to bootstrap an
# admin API key, so the user must have manage_security plus enough
# privileges to seed sample data — `superuser` works for local dev.

npm run test:permissions
```

Exit code is `0` if every check passes (or is skipped); `1` otherwise.

## Flags

| Flag | Description |
|---|---|
| `--mode stateful\|serverless` | Deployment mode (default: `stateful`). Changes the default admin username and enables serverless role aliases. |
| `--role <name\|alias>` | Which role(s) to test (default: `both`). See below for valid names and aliases. |
| `--cleanup-stale` | Delete leftover `mcp-app-test-*` roles and API keys before running. Useful after a crashed run. |
| `--no-cleanup` | Skip cleanup at the end and print the provisioned API keys so you can re-use them for manual debugging. |
| `--verbose`, `-v` | Print fixtures, stale-cleanup actions, and other debug info. |
| `-h`, `--help` | Show help. |

**`--role` values:**

| Value | Expands to |
|---|---|
| `full` | Custom full-access role |
| `readonly` | Custom read-only role |
| `both` (default) | `full` + `readonly` |
| `all` | `full` + `readonly` + `quickstart_full` + `quickstart_readonly` |
| `quickstart_full` | Quickstart built-in `editor` + companion role |
| `quickstart_readonly` | Quickstart built-in `viewer` + companion role |
| `quickstart` | `quickstart_full` + `quickstart_readonly` |
| `serverless_t1_analyst` | Serverless built-in `t1_analyst` user (observe-only) |
| `serverless_t2_analyst` | Serverless built-in `t2_analyst` user (observe-only) |
| `serverless_soc_manager` | Serverless built-in `soc_manager` user (observe-only) |
| `serverless` | All 3 serverless built-in roles |
| `serverless_all` | All stateful asserted + all serverless observe-only |
| `none` | No roles (cleanup-stale only) |

Pass flags via `--`, e.g. `npm run test:permissions -- --role readonly --verbose`.

## Serverless mode

For Elastic Cloud Serverless (Security project type), start a local serverless cluster and then run:

```bash
# Start serverless ES (port 9200)
yarn es serverless --projectType=security

# Start serverless Kibana (port 5601)
yarn start --serverless=security

# In example-mcp-app-security, configure .env:
# ELASTICSEARCH_URL=http://localhost:9200
# KIBANA_URL=http://localhost:5601/kbn
# ELASTIC_PASSWORD=changeme
# (ELASTIC_USERNAME defaults to "elastic_serverless" in serverless mode)

npm run test:permissions:serverless
```

The serverless runner uses `--mode serverless`, which:
- Defaults admin username to `elastic_serverless` (instead of `elastic`)
- Authenticates the three built-in role users (`t1_analyst`, `t2_analyst`, `soc_manager`) via `grant_api_key` — they exist as file-realm users with password `changeme`
- Runs each built-in role in **observe-only mode**: all operations are exercised and results are printed, but no assertions are made. The exit code is only affected by the asserted custom roles (`full`, `readonly`) if those are also included

Custom roles (`full`, `readonly`) work on serverless too — `PUT /_security/role` is supported since the GA of custom roles in Serverless Security (Oct 2024).

To run both built-in observed roles and custom asserted roles against serverless in one pass:

```bash
npm run test:permissions:serverless:all
```

### Output for serverless built-in roles

Observed reports look like:

```
── SERVERLESS_VIEWER (observe-only) ──
  Layer A: skipped (built-in role — privileges not enumerable from a role descriptor)
  Layer B (operations, observed — no pass/fail assertions):
    [alerts]
      ✓ fetchAlerts — pass: array(1)
      ✓ acknowledgeAlert — pass: ok
      ...
    [rules]
      ✗ createRule — 403: denied (403/401)
      ...
```

Symbols show what actually happened: `✓` = call succeeded, `✗` = 403/401, `→` = skipped or other. These results inform [`docs/permissions-serverless.md`](../../docs/permissions-serverless.md).

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

**`Fatal error: ELASTICSEARCH_URL, KIBANA_URL, and ELASTIC_PASSWORD must be set...`**
`.env` isn't loading or is missing one of `ELASTICSEARCH_URL`, `KIBANA_URL`, `ELASTIC_PASSWORD`. `ELASTIC_USERNAME` is optional (defaults to `elastic` in stateful mode, `elastic_serverless` in serverless mode). The script reads them via `dotenv/config`.

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

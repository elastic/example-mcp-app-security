# Shared serverless instance for E2E and evals

The MCP App repo ships live integration harnesses (`npm run test:e2e`, `npm run test:evals`) that run against a **shared** Elastic serverless cluster — not mocks. Treadmill's runtime quality gates invoke the same scripts when credentials are configured on the daemon host.

## Credentials file

Create a JSON file (never commit it) with the same shape as `CLUSTERS_FILE` / `CLUSTERS_JSON`:

```json
[
  {
    "name": "shared-e2e",
    "elasticsearchUrl": "https://…es…",
    "kibanaUrl": "https://…kb…",
    "elasticsearchApiKey": "…"
  }
]
```

Recommended path on the treadmill host:

```text
~/.treadmill/mcp-e2e-clusters.json
```

Add to `~/.treadmill/secrets.env`:

```bash
TREADMILL_MCP_E2E_CLUSTERS_FILE=$HOME/.treadmill/mcp-e2e-clusters.json
# Require E2E/evals in CI gates (fail instead of skip when file missing):
MCP_E2E_REQUIRED=1
```

Resolution order (first existing file wins):

1. `TREADMILL_MCP_E2E_CLUSTERS_FILE`
2. `MCP_E2E_CLUSTERS_FILE`
3. `CLUSTERS_FILE`
4. `~/.treadmill/mcp-e2e-clusters.json`

## What the harness does

| Script | Command | Behavior |
|--------|---------|----------|
| E2E | `npm run test:e2e` | Seeds sample data when sparse, then calls `poll-alerts`, `list-cases`, `find-rules`, `list-indices` via in-process MCP client, then an Attack Discovery generation smoke test |
| Evals | `npm run test:evals` | Runs scenario table in `scripts/evals/scenarios.ts` — asserts JSON shapes from live tool responses |

Both skip cleanly when no credentials file exists (exit 0) unless `MCP_E2E_REQUIRED=1`.

### Attack Discovery generation smoke test

`npm run test:e2e` includes a generation smoke test (guarding against
[#46](https://github.com/elastic/example-mcp-app-security/issues/46): a silent
`camelCase`/`snake_case` param mismatch that truncated the anonymization
field list and starved the LLM prompt of context). It selects an AI
connector, triggers `generate-attack-discovery`, polls to a terminal status,
and asserts `discoveries > 0` against seeded sample data.

Discovery count depends on a live LLM's non-deterministic output, so this
assertion is **skipped by default in CI** (detected via `CI=true`/`CI=1`) to
avoid flaking unattended runs — it's intended as a manual/local regression
check. Control it explicitly with `MCP_E2E_ATTACK_DISCOVERY_SKIP`:

- `1` — always skip (e.g. to bypass local flakiness)
- `0` — always run, even in CI
- unset — runs locally, skips automatically when `CI` is set

`MCP_E2E_ATTACK_DISCOVERY_TIMEOUT_MS` overrides the poll timeout (default 15
minutes — generation runs two sequential LLM round-trips and can be slow
behind an overloaded connector).

## Local run

```bash
npm ci && npm run build
export TREADMILL_MCP_E2E_CLUSTERS_FILE=$HOME/.treadmill/mcp-e2e-clusters.json
npm run test:e2e
npm run test:evals
```

## Treadmill gates

When `isMcpAppProject()` and a clusters file is resolved on the daemon, `detect-checks` adds runtime gates:

- `mcp-e2e` → `npm run test:e2e`
- `mcp-evals` → `npm run test:evals`

Static gates still run `typecheck`, `build`, `lint`, `test:run`, and `mcp-smoke` first — build must succeed before live cluster tests.

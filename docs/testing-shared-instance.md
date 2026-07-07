# Shared serverless instance for E2E and evals

The MCP App repo ships live integration harnesses (`npm run test:e2e`, `npm run test:evals`) that run against a **shared** Elastic serverless cluster — not mocks.

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

Default path:

```text
~/.mcp-e2e/clusters.json
```

Resolution order (first existing file wins):

1. `MCP_E2E_CLUSTERS_FILE`
2. `CLUSTERS_FILE`
3. `~/.mcp-e2e/clusters.json`

## What the harness does

| Script | Command | Behavior |
|--------|---------|----------|
| E2E | `npm run test:e2e` | Seeds sample data when sparse, then calls `poll-alerts`, `list-cases`, `find-rules`, `list-indices` via in-process MCP client, then an Attack Discovery generation smoke test |
| Evals | `npm run test:evals` | Runs scenario table in `scripts/evals/scenarios.ts` — asserts JSON shapes from live tool responses |

Both skip cleanly when no credentials file exists (exit 0) unless `MCP_E2E_REQUIRED=1`.

### Attack Discovery generation smoke test

`npm run test:e2e` includes a generation smoke test guarding against
[#46](https://github.com/elastic/example-mcp-app-security/issues/46) — a silent
`camelCase`/`snake_case` param mismatch that truncated the anonymization
field list and starved the LLM prompt of context. It selects an AI
connector, triggers `generate-attack-discovery`, polls to a terminal status,
and asserts `discoveries > 0` against seeded sample data.

Discovery count depends on a live LLM's non-deterministic output, so this
assertion is **skipped by default in CI** (detected via `CI=true`/`CI=1`) to
avoid flaking unattended runs — it's a manual/local regression check.
Control it explicitly with `MCP_E2E_ATTACK_DISCOVERY_SKIP`:

- `1` — always skip (e.g. to bypass local flakiness)
- `0` — always run, even in CI
- unset — runs locally, skips automatically when `CI` is set

`MCP_E2E_ATTACK_DISCOVERY_TIMEOUT_MS` overrides the poll timeout (default 15
minutes — generation runs two sequential LLM round-trips and can be slow
behind an overloaded connector).

## Local run

```bash
npm ci && npm run build
export MCP_E2E_CLUSTERS_FILE=$HOME/.mcp-e2e/clusters.json
npm run test:e2e
npm run test:evals
```

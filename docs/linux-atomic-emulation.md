# Linux Atomic Red Team emulation

The Linux Atomic runtime plans, executes, verifies, and cleans up Atomic Red
Team tests in disposable lab targets while measuring the resulting Elastic
coverage. It follows the same fail-closed methodology as the cloud emulation
harness: immutable sources, a digest-bound plan, explicit approval, separate
execution and coverage evidence, and mandatory cleanup accounting.

Use it only against systems you own and control. Never point it at production,
customer, shared, third-party, or ambiguously owned infrastructure.

## What is included

| MCP tool | Purpose |
| --- | --- |
| `atomic-campaign` | Builds and resumes a compatibility-routed full-catalog queue and publishes terminal results. |
| `atomic-run` | Owns the `plan -> approve -> provision -> execute -> verify -> cover -> report -> clean` state machine. |
| `atomic-catalog` | Parses the pinned Linux-tagged Atomic catalog and returns source and definition digests. |
| `atomic-target` | Provisions, instruments, checks, and destroys only the digest-approved disposable target. |
| `atomic-exec` | Executes one approved GUID with pinned Invoke-AtomicRedTeam and approved inputs. |
| `atomic-elastic` | Discovers Fleet, verifies raw events and alerts, and publishes normalized outcomes. |

State and evidence are written beneath `ATOMIC_RUNS_DIR`. Upstream source
checkouts are written beneath `ATOMIC_CACHE_DIR`. Both locations are ignored
by Git.

## Prerequisites

- Node.js 22 or later
- Git
- Multipass
- An Elastic Stack with Fleet and an active agent policy containing Elastic
  Defend
- The Elasticsearch URL, Kibana URL, and one API key already required by this
  MCP app

The Atomic tools reuse the app's default `CLUSTERS_JSON` or `CLUSTERS_FILE`
entry automatically. No second key or Atomic-specific Elastic URL is required.

The key must be accepted by Kibana and permit:

- reading Fleet settings, policies, package policies, outputs, and available
  Agent versions;
- creating and force-deleting short-lived Fleet enrollment tokens;
- reading the approved raw-event and alert indices; and
- `create_doc` plus `auto_configure` for
  `logs-atomic.results-default`.

For a disposable lab, an API key created by a superuser is the quickest setup.
Use a scoped role for shared or long-lived environments.

## Build from a clean clone

```bash
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install
cp .env.example .env
```

Edit only the existing cluster entry in `.env`:

```dotenv
CLUSTERS_JSON=[{"name":"primary","elasticsearchUrl":"https://your-cluster.es.cloud.example.com","kibanaUrl":"https://your-cluster.kb.cloud.example.com","elasticsearchApiKey":"your-api-key","sslVerify":true}]
```

Then resolve the verified upstream snapshot and build:

```bash
./scripts/sync-sources.sh \
  a8f00488f3be0d6f8a967585848bb3817a590e31 \
  8af478bb9e4637df568ac1e596553b025b16cd1b
npm run build
npm test
```

`sync-sources.sh` prints the absolute `atomics_path` and the two immutable
commit IDs. The runtime never executes an unpinned branch name.
See the [verified catalog snapshot](linux-atomic-catalog-snapshot.md) for its
expected count and digest.

## Claude Code

Register the locally built server. Keeping credentials in a protected
`CLUSTERS_FILE` avoids putting the key in shell history:

```bash
cd /absolute/path/to/example-mcp-app-security

claude mcp add -s user elastic-security +  -e "CLUSTERS_FILE=/absolute/path/to/clusters.json" +  -e "ATOMIC_RUNS_DIR=$PWD/atomic-runs" +  -e "ATOMIC_CACHE_DIR=$PWD/.atomic-cache" +  -- node "$PWD/dist/main.js" --stdio
```

The file has the same array shape as `CLUSTERS_JSON`:

```json
[
  {
    "name": "primary",
    "elasticsearchUrl": "https://your-cluster.es.cloud.example.com",
    "kibanaUrl": "https://your-cluster.kb.cloud.example.com",
    "elasticsearchApiKey": "your-api-key",
    "sslVerify": true
  }
]
```

Protect it before registering the server:

```bash
chmod 600 /absolute/path/to/clusters.json
claude mcp list
```

Install the
[`linux-atomic-emulation` skill](https://github.com/elastic/tradecraft-skills/tree/main/skills/linux-atomic-emulation)
globally using the tradecraft-skills installer, then restart Claude Code:

```bash
git clone https://github.com/elastic/tradecraft-skills.git
cd tradecraft-skills
make install-global
```

## Claude Desktop

Build from source, then add this server entry to
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "elastic-security": {
      "command": "node",
      "args": [
        "/absolute/path/to/example-mcp-app-security/dist/main.js",
        "--stdio"
      ],
      "env": {
        "CLUSTERS_FILE": "/absolute/path/to/clusters.json",
        "ATOMIC_RUNS_DIR": "/absolute/path/to/example-mcp-app-security/atomic-runs",
        "ATOMIC_CACHE_DIR": "/absolute/path/to/example-mcp-app-security/.atomic-cache"
      }
    }
  }
}
```

Restart Claude Desktop after changing the configuration. Upload the packaged
`linux-atomic-emulation` skill when it becomes available, or use the same
skill directory from a tradecraft-skills clone.

## Run one test

Start a fresh conversation and use the skill with the Atomic GUID:

```text
/linux-atomic-emulation Start a completely fresh run for Atomic test
4ff61684-ad91-405c-9fbc-048354ff1d07. Use a disposable Multipass target,
automatically enroll it in the configured Elastic Defend policy, verify raw
events and attributable alerts, publish the terminal result, and clean up.
```

The skill must stop after presenting the plan digest. Execution remains locked
until the engineer explicitly approves that exact digest.

## Run the full Linux-tagged catalog

```text
/linux-atomic-emulation Create a fresh full-catalog campaign from the pinned
Atomic sources. Route compatible tests into safe batches, isolate tests that
can contaminate later results, automatically enroll every Linux VM in the
configured Elastic Defend policy, publish every terminal result, and continue
until the campaign can be finalized. FreeBSD-only variants must be logged and
published as skipped without provisioning.
```

The campaign groups only tests that can safely share a target. Tests involving
reboots, shutdowns, kernel changes, persistence, destructive behavior, special
runtimes, GUI interaction, or other cross-test contamination risks receive an
exclusive route. A compatibility finding is re-routed through a new approved
plan instead of silently becoming the final result.

FreeBSD-only variants are never executed because Elastic Agent and Elastic
Defend do not support target-side FreeBSD telemetry. They are still written to
the campaign ledger and published with `outcome: skipped`, platform fields,
the skip reason, and Kibana log and alert navigation links.

## Outcome model

- `detected`: the approved behavior succeeded, matching raw telemetry exists,
  and an attributable alert exists.
- `missed`: the approved behavior succeeded and matching raw telemetry exists,
  but no attributable alert exists.
- `no_telemetry`: the approved behavior succeeded but no usable raw telemetry
  was found.
- `not_applicable`: the behavior or detector could not be evaluated as
  planned; compatibility cases should be re-routed before accepting this as a
  terminal campaign result.
- `skipped`: an unsupported target variant was intentionally not provisioned
  or executed, but its complete audit record was published.

Runner exit status alone is never treated as behavior success. Each plan binds
test-specific success assertions, telemetry queries, cleanup expectations, and
the exact target route.

## Security and cleanup

- Atomic YAML, commands, prerequisites, payloads, and output are untrusted data.
- The host never evaluates Atomic command fields.
- Enrollment tokens are created for one hour, passed to the guest over stdin,
  redacted from evidence, and force-deleted immediately after enrollment.
- API keys are not stored in plans, run state, result documents, or reports.
- Finalization fails while an expected cleanup or resource remains
  unaccounted for.

See [Linux Atomic architecture](linux-atomic-architecture.md) for the trust
boundaries and state-machine invariants.

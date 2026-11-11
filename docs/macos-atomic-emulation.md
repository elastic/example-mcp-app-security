# macOS Atomic Red Team emulation

The macOS Atomic runtime plans, executes, verifies, and cleans up Atomic Red
Team tests while measuring the resulting Elastic coverage. It uses immutable
sources, a digest-bound plan, explicit approval, separate behavior and
telemetry evidence, and mandatory cleanup accounting.

Use it only on disposable systems you own and control. Never route a campaign
to a production, customer, shared, third-party, or ambiguously owned Mac.

## What is included

| MCP tool | Purpose |
| --- | --- |
| `macos-atomic-campaign` | Builds and resumes the full macOS catalog with architecture and capability routing. |
| `macos-atomic-run` | Owns the plan, approval, execution, coverage, report, and cleanup state machine. |
| `macos-atomic-catalog` | Parses macOS-tagged Atomics and returns immutable definition, asset, and catalog digests. |
| `macos-atomic-target` | Provisions Tart targets or registers approved SSH Macs, then verifies and cleans them. |
| `macos-atomic-exec` | Runs one approved GUID through pinned Invoke-AtomicRedTeam or an approved operator procedure. |
| `macos-atomic-elastic` | Discovers Fleet, verifies raw events and attributable alerts, and publishes outcomes. |

State and evidence are written below `MACOS_ATOMIC_RUNS_DIR`. Source checkouts
are written below `MACOS_ATOMIC_CACHE_DIR`. Both directories are ignored by
Git.

## Host prerequisites

The disposable Tart route requires an Apple Silicon Mac running macOS 13 or
later, Node.js 22 or later, Git, and Tart. Install the host tools:

```bash
brew install openai/tools/tart crane
```

Resolve a public macOS 15 base image to an immutable OCI digest:

```bash
IMAGE_TAG=ghcr.io/cirruslabs/macos-sequoia-base:latest
IMAGE_DIGEST="$(crane digest "$IMAGE_TAG")"
echo "ghcr.io/cirruslabs/macos-sequoia-base@$IMAGE_DIGEST"
```

Use the printed `ghcr.io/...@sha256:...` value as `scope.target_image`.
The harness rejects mutable tags. Official non-vanilla Cirrus Labs images
include Homebrew, passwordless sudo for the `admin` user, and the Tart guest
agent. The runtime uses `tart exec`; no SSH key is required for this route.

The plan adds one reviewed setup step when PowerShell is absent:

```json
{
  "description": "Install PowerShell for Invoke-AtomicRedTeam",
  "command": ["/opt/homebrew/bin/brew", "install", "--cask", "powershell"],
  "elevated": false
}
```

That exact argv is part of the plan digest. The runtime installs
`powershell-yaml` only after the approved setup steps finish.

## Elastic prerequisite

Use an Elastic Agent policy that contains Elastic Defend. The Atomic tools
reuse this app's existing default cluster configuration; they do not require a
second Elastic URL or API key. The key must allow Fleet discovery, creation
and force-deletion of short-lived enrollment tokens, reading the approved
event and alert indices, and writing `logs-atomic.results-default`.

macOS requires Apple-controlled approvals for the Elastic Endpoint system
extension, network content filter, and Full Disk Access. For a one-off desktop
run, approve the prompts while the VM window is open. For an unattended full
catalog, use an MDM-enrolled target whose profile pre-approves those items.
The harness does not bypass or weaken these controls. Do not capture an
already enrolled Agent in a reusable image: cloning it would duplicate the
Agent identity. Each run creates a temporary enrollment token, enrolls the
fresh target, and immediately revokes the token.

See Elastic's [macOS access guide](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/enable-access-for-macos)
and [MDM deployment guide](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/deploy-on-macos-with-mdm).

## Build from a clean clone

```bash
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install
cp .env.example .env
```

Set the existing cluster entry in `.env`:

```dotenv
CLUSTERS_JSON=[{"name":"primary","elasticsearchUrl":"https://your-cluster.es.cloud.example.com","kibanaUrl":"https://your-cluster.kb.cloud.example.com","elasticsearchApiKey":"your-api-key","sslVerify":true}]
```

Resolve the verified source snapshot and build:

```bash
./scripts/sync-macos-atomic-sources.sh \
  a8f00488f3be0d6f8a967585848bb3817a590e31 \
  8af478bb9e4637df568ac1e596553b025b16cd1b
npm run build
npm run test:run
```

The sync script prints the absolute `atomics_path` and both immutable commit
IDs. See the [verified snapshot](macos-atomic-catalog-snapshot.md).

## Claude Code

Store the cluster array in a protected file, then register the server:

```bash
chmod 600 /absolute/path/to/clusters.json
cd /absolute/path/to/example-mcp-app-security
claude mcp add -s user elastic-security \
  -e "CLUSTERS_FILE=/absolute/path/to/clusters.json" \
  -e "MACOS_ATOMIC_RUNS_DIR=$PWD/macos-atomic-runs" \
  -e "MACOS_ATOMIC_CACHE_DIR=$PWD/.macos-atomic-cache" \
  -- node "$PWD/dist/main.js" --stdio
claude mcp list
```

Install the `macos-atomic-emulation` skill from `elastic/tradecraft-skills`,
restart Claude Code, and invoke it with a GUID or a full campaign request.

## Claude Desktop

Add this entry to
`~/Library/Application Support/Claude/claude_desktop_config.json` and restart
Claude Desktop:

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
        "MACOS_ATOMIC_RUNS_DIR": "/absolute/path/to/example-mcp-app-security/macos-atomic-runs",
        "MACOS_ATOMIC_CACHE_DIR": "/absolute/path/to/example-mcp-app-security/.macos-atomic-cache"
      }
    }
  }
}
```

## Run one test

```text
/macos-atomic-emulation Start a completely fresh run for Atomic test
<GUID>. Use a disposable Tart target, automatically enroll it in the configured
Elastic Defend policy, verify behavior plus attributable raw events and alerts,
publish the terminal result, and clean up.
```

The skill stops after presenting the exact plan digest. Planning approval does
not authorize execution; execution remains locked until the engineer approves
that digest.

## Run the complete catalog

```text
/macos-atomic-emulation Create a fresh full-catalog campaign from the pinned
Atomic sources. Route compatible Apple Silicon tests into safe batches,
isolate contaminating tests, route Intel/custom/real-hardware tests to approved
SSH Macs, publish every terminal result, and continue until finalization.
```

The campaign never treats compatibility as a permanent skip. Normal Apple
Silicon tests use Tart. Intel-only, special-runtime, SIP/TCC, and real-hardware
tests use explicit SSH routes. Manual and GUI tests open a Tart desktop or use
an approved desktop Mac and require an operator evidence record. Tests that
can affect later tests receive an exclusive target.

## Outcomes

- `detected`: approved behavior succeeded, matching raw telemetry exists, and
  at least one alert is attributable to the test.
- `missed`: approved behavior succeeded and matching raw telemetry exists, but
  no attributable alert exists.
- `no_telemetry`: approved behavior succeeded but no matching raw telemetry was
  found.
- `not_applicable`: behavior did not complete or the approved detector could
  not be evaluated; campaigns re-route the compatibility case before accepting
  it as terminal.

Every result includes `host.os.type: macos`, architecture and target fields,
the behavior result, coverage counts and reason, and Kibana log/alert links.
Runner exit status alone never proves behavior success.

## Security and cleanup

- Atomic YAML, support assets, commands, and output are untrusted data.
- The host never evaluates command strings from Atomic YAML.
- Tart images, upstream commits, test definitions, assets, plans, and approvals
  are digest-bound.
- Enrollment tokens are short-lived, sent only to the target, redacted from
  evidence, and force-deleted immediately after enrollment.
- API keys are never stored in plans, run state, reports, or result documents.
- Finalization fails while cleanup or any provisioned resource is unaccounted
  for.

See [macOS Atomic architecture](macos-atomic-architecture.md) for the trust
boundaries and routing model.

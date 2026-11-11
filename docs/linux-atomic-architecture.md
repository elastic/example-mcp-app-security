# Linux Atomic emulation architecture

## Control and execution planes

The MCP server is the control plane. It parses metadata, stores approved state,
provisions approved targets, invokes a pinned runner, queries bounded telemetry,
and records evidence. It never evaluates an Atomic YAML command on the host.

The disposable Linux guest is the execution plane. Invoke-AtomicRedTeam reads
the pinned Atomic repository and executes exactly one approved GUID with the
approved input map.

```text
engineer and agent
        |
        v
atomic-campaign ---- pinned compatibility queue and publication status
        |
        +--> atomic-run ----- private JSON state and evidence ledger
                |
                +--> atomic-catalog  read-only pinned YAML
                +--> atomic-target   target and Fleet lifecycle
                +--> atomic-exec     approved GUID and inputs
                +--> atomic-elastic  bounded verification and publication
```

## State-machine invariants

- `set_plan` canonicalizes the plan into a SHA-256 digest and moves the run to
  `awaiting_approval`.
- `approve` accepts only the currently stored digest.
- Source and runner revisions must be immutable 40-character commits.
- Every test binds its definition digest and every required support file binds
  its path, size, and SHA-256.
- Target profile, capabilities, execution user, elevation, fixtures, packages,
  setup steps, behavior assertions, telemetry queries, and cleanup expectations
  are part of the approved digest.
- A passed execution requires both runner success and
  `behavior_success: true`.
- Applicable coverage is rejected unless approved behavior success was
  confirmed.
- Coverage and cleanup are independent outcomes.
- Finalization checks every planned GUID and every expected resource.
- A shared VM is permitted only for a compatibility batch classified as safe.
  Contamination-sensitive tests receive a fresh target.
- FreeBSD-only entries are terminal audit skips and never receive a target.

## Trust boundaries

Atomic YAML, payloads, documentation, prerequisite commands, test output, and
telemetry fields are untrusted. They are data, not agent instructions.

Host-side process execution uses argument arrays without an intermediate shell.
Atomic input maps are encoded and decoded inside the guest rather than
interpolated into a host command.

Fleet discovery reads the configured Kibana APIs, selects an active policy with
Elastic Defend, resolves Fleet Server and Elasticsearch output endpoints, and
selects the newest compatible published GA Elastic Agent. The selected versions
and identifiers become part of the plan digest and are revalidated before
provisioning.

The coverage verifier accepts only queries already present in the approved
plan, applies a bounded time range and index allowlist, and uses count-only
requests. Result publication writes a local NDJSON outbox before idempotently
indexing one deterministic current-result document per campaign and GUID.

## Target adapters

- Multipass provides full provision, instrumentation, health, reboot/stop
  verification, and destruction for disposable Linux targets.
- Desktop routes add a reviewed GUI profile for manual browser tests.
- Existing Docker or SSH targets are permitted only when explicitly
  digest-bound; their lifecycle remains the engineer's responsibility.
- FreeBSD-only variants are logged and published as unsupported skips.

Automatic destruction is limited to the exact ephemeral target identifier
stored in the approved plan and resource ledger.

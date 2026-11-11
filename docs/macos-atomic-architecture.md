# macOS Atomic architecture

The runtime separates planning authority, target mutation, behavior evidence,
coverage attribution, and cleanup. No single successful command can advance a
run through all gates.

## Trust boundaries

1. The catalog parser reads only a pinned Atomic Red Team checkout and hashes
   each definition and support asset.
2. The run state machine persists an exact plan and stops at
   `awaiting_approval` with its SHA-256 digest.
3. The target tool provisions only the approved OCI-digest Tart image or
   registers the exact SSH target in the plan.
4. The execution tool runs only the approved GUID, inputs, elevation mode,
   fixtures, and setup commands through pinned Invoke-AtomicRedTeam. Manual
   tests require reviewed steps and an operator attestation.
5. Behavior-specific assertions must pass before Elastic coverage is scored.
6. Raw-event and alert queries are plan-bound and time-bounded. A detected
   label requires both successful behavior and an attributable alert query.
7. Result publication uses deterministic campaign/GUID document IDs, so retry
   updates the same result instead of duplicating it.
8. Cleanup accounts for every Tart VM and temporary Fleet enrollment token.

## Target routing

| Test requirement | Route |
| --- | --- |
| Normal arm64 or architecture-neutral shell/PowerShell | Digest-pinned ephemeral Tart VM |
| GUI or manual behavior | Tart desktop VM with operator evidence |
| Intel-only behavior | Approved x86_64 SSH Mac |
| Special runtime, SIP/TCC changes | Approved custom SSH Mac |
| Secure Enclave, firmware, Touch ID, or other physical hardware | Approved real-hardware SSH Mac |

Tart uses `tart exec` through the guest agent, including stdin for bootstrap
scripts and one-time enrollment tokens. SSH is reserved for routes where Apple
Virtualization cannot reproduce the required behavior.

## Isolation

Only catalog entries proven read-only and free of cleanup requirements can
share a target. Elevated, state-changing, persistent, network, kernel, GUI,
manual, destructive, rebooting, TCC/SIP, special-runtime, and real-hardware
tests are exclusive. A shared target is destroyed and replaced whenever a
test leaves unexplained state.

## Apple security controls

The runtime verifies Elastic Agent health and the Elastic Endpoint system
extension. It does not bypass system-extension approval, network-filter
approval, Full Disk Access, TCC, SIP, or Secure Boot. Desktop operators can
approve one-off prompts; unattended campaigns require an MDM-managed target.

## Result document

Results are indexed into `logs-atomic.results-default` by default. Documents
include campaign/run identity, immutable source and plan digests, macOS version
and architecture, target route, execution and cleanup evidence, normalized
coverage outcome, raw-event and alert counts, and Kibana navigation links.
Secrets and enrollment tokens are excluded.

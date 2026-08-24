# Optional internal hooks

The public run harness is the `emulation-run` MCP tool in this app. Use it for phase
order, digest-bound approval, the resource ledger, and finalize. Do not substitute a
markdown journal for that state machine.

This public skill does not ship the private lab OS. If those components exist in the
agent environment, use them *in addition* to `emulation-run`. **Do not block a
methodology run on their absence.**

They are the follow-up blog / internal skill, not a prerequisite for this repo.

| Hook | What it is | If missing (public path) |
| --- | --- | --- |
| Event journal + `track` argv | Append-only run events, digest-bound `gate-request`, exact-ID ledger, command wrapper | `emulation-run` (`init` / `set_plan` / `approve` / `record_*` / `finalize`) |
| Lab allowlist + scope guard | Fail-closed check that the caller is in a listed disposable account/sub/project | Engineer names the owned lab at the checkpoint; refuse customer/prod/third-party |
| Detection pipeline | Per-action author → repo validate → live import → observe alert → remove | `threat-hunt` + `manage-rules`; score coverage; hand off drafted opportunities |
| `trade-lab` MCP | Lab Elastic / Fleet | This `elastic-security` connector |
| VM / Fleet instrumentation | Guest Elastic Agent on lab compute | Control-plane telemetry only |

Do not copy private scripts, allowlists, Fleet enrollment, or detection-rules staging
workflows into this skill. If a hook is present, follow *its* docs; this file is only a
pointer.

Fillers the agent may emit so a phase does not look skipped by accident:

- **Journal absent:** "No event journal hook; `emulation-run` is the system of record."
- **Allowlist absent:** "No scope guard; engineer confirmed account/sub/project `<id>` as owned disposable lab."
- **Pipeline absent:** "No author/validate/verify pipeline; coverage scored against live rules; no staged TOML."
- **No compute target:** skip guest instrumentation; control-plane only.

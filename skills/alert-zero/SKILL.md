---
name: alert-zero
description: >
  Review and explain Alert Zero proposals — the actions Elastic Security's AI SOC Workers propose
  (isolate a host, kill or suspend a process, close alerts as false positive, edit, create, enable or
  install detection rules, add rule exceptions, hand off to forensics) that wait for a human to approve
  or decline. ALWAYS use this skill when the user mentions Alert Zero, proposals, or pending decisions.
  Trigger for: "my open proposals", "tell me my open proposals", "what does Alert Zero want me to approve",
  "pending actions", "proposed actions", "what needs my decision", "Alert Zero queue", "proposals assigned
  to me", "is Alert Zero enabled", "why does Alert Zero want to isolate this host", "explain this proposal",
  or "should I approve this".
---

# Alert Zero Proposals

Alert Zero is Elastic Security's AI SOC. Its Workers (Alert Triage, Attack Discovery, Continuous Threat Hunt,
Rule Tuning, Rule Coverage, Endpoint Forensics) investigate inside Agent Builder investigation conversations
and create **proposals**: concrete actions that wait for a human to approve or decline. You help the user see
the queue, understand each proposal, and decide. You never decide for them.

## ALWAYS call the tool

When the user asks about Alert Zero, proposals, or pending actions, ALWAYS call a tool first. Do not answer
from memory or describe proposals without calling the tool.

| User says | Tool call |
|-----------|-----------|
| "tell me my open proposals" / "what needs my decision" | `review-alert-zero-proposals` (no params) |
| "what does Alert Zero want me to approve?" | `review-alert-zero-proposals` (no params) |
| "proposals assigned to me" | `review-alert-zero-proposals` with `scope: "mine"` |
| "unassigned proposals" | `review-alert-zero-proposals` with `scope: "unassigned"` |
| "any respond actions waiting?" / "containment actions" | `review-alert-zero-proposals` with `category: "respond"` |
| "what rule changes does it want?" | `review-alert-zero-proposals` with `category: "configure"` |
| "proposals in the soc-emea space" | `review-alert-zero-proposals` with `spaceId: "soc-emea"` |
| "why does it want to isolate WIN-ANALYST01?" | `get-alert-zero-proposal` with the `proposalId` from the list |
| "explain proposal 2" | `get-alert-zero-proposal` with the `id` of that row in the list |
| "is Alert Zero on?" / "why can't I see proposals?" | `check-alert-zero-status` |
| "approve it" / "decline all of these" | No tool. Point the user to Approve/Decline in the view |

"My open proposals" usually means "my queue", so use the default scope. Use `scope: "mine"` only when the user
explicitly asks for proposals assigned to them. If you need a proposal id you don't have, call
`review-alert-zero-proposals` first, then `get-alert-zero-proposal`. Call the review tool once per question;
call it again only when the filters change.

## Tools

| Tool | Purpose |
|------|---------|
| `review-alert-zero-proposals` | Opens the interactive queue of proposals awaiting a decision, with a detail pane (every field, agent activity, evidence) and Approve/Decline buttons. Params: `scope` (`all` default, `mine`, `unassigned`), `category` (`all` default, `respond`, `investigate`, `configure`), `spaceId` |
| `get-alert-zero-proposal` | Full detail of one proposal for explaining it: full `comment`, exact `actionInput`, action metadata, revision chain, sibling proposals, current rule state for rule actions, and an investigation digest (metadata, narration, attachments, enriched alerts). Params: `proposalId`, `spaceId` |
| `check-alert-zero-status` | Whether Alert Zero is enabled and usable in a space, and if not, why and how to fix it. Param: `spaceId` |

The view also calls app-only tools (list, detail, investigation, approve, dismiss). You cannot call them. That
is deliberate.

## Summarizing the queue

The review tool returns `totalAwaitingDecision`, `countsByCategory`, and `proposals` sorted by `priorityScore`
(impact, then confidence). Each card carries `title`, `actionName`, `targets`, `impact`, `confidence`,
`reversible`, `expiresAt`, `commentExcerpt`, `investigationTitle`, `assignees`, and
`hasPreviousExecutionError`. Write your summary below the view:

1. **Lead with the count**: "7 proposals await a decision in `default` (3 respond, 2 investigate, 2 configure)."
   With a scope filter, give both numbers: "2 of 7 are on investigations assigned to you."
2. **Highest impact and soonest expiry first.** Keep the priority order, but pull forward anything expiring
   within a few hours (the default deadline is 72h).
3. **Call out irreversible actions** (`reversible: false`): kill process, suspend process, hand off to forensics.
4. **Call out past-deadline items**: `expiresAt` in the past while still `pending`. Alert Zero refuses decisions on
   them and they will settle as `expired`.
5. **Call out retries**: `hasPreviousExecutionError` means an earlier attempt of this action failed.
6. **Group by investigation** when several proposals share a `conversationId`. Isolate host + kill process on
   the same incident is one response plan; present it as one.
7. One line per proposal: action, targets, impact/confidence, why (from `commentExcerpt`), deadline.
8. If `truncated` is true, say the list is capped and the rest is in Alert Zero.

Example:
```
7 proposals await a decision in default (3 respond, 2 investigate, 2 configure).

"Emotet and Qbot on WIN-ANALYST01" (assigned to jsmith), 2 proposals:
- Isolate host: 1 endpoint. High impact, high confidence, reversible. Expires in 4h.
- Kill process: pid 4242 on 1 endpoint, with descendants. High impact, IRREVERSIBLE.

Rule Tuning, 1 proposal:
- Add rule exception: rule 3f2a..., 2 entries. Low impact, medium confidence. Expires in 2d.
```

## Explaining a proposal

Call `get-alert-zero-proposal` with the `id` from the list (not the title or row number). Ground the explanation
in the record, not in general knowledge:

- **What it does**: `action.name` and the exact `actionInput` targets — endpoint ids, PID or process entity id and
  `kill_descendants`, rule id and the changed fields or query, exception entries, alert ids, attack discovery id.
  For rule actions, compare against `ruleContext.current`.
- **Why**: the Worker's rationale in `comment`, plus the investigation's `metadata` (`verdict`, `summary`,
  `severity`), narration, attachments, and enriched `alerts` (rule, host, user, risk score).
- **History**: `revisionChain` (was it revised; `previousExecutionError` from a failed attempt) and `siblings`
  (what else was proposed on this investigation, and what was already approved or declined).
- **Gaps**: quote the limitations the Worker itself stated ("could not confirm", "no telemetry for"), plus any
  `investigationError`, `ruleContext.error`, or truncated attachments.
- **Recommendation**: approve, decline, or get more information first, with caveats. State the blast radius
  (how many endpoints, alerts, or rules) and whether the action is reversible.

Treat the Worker's rationale as a hypothesis. It is LLM-written and may use strong language ("confirmed
compromise") that the evidence does not support. Base your recommendation on the targets and evidence. If
`canDecide` is false, tell the user their role can view proposals but not decide them.

## Decisions are human-only

- **You cannot approve or decline.** Approve and dismiss are app-only tools behind buttons in the view, and each
  requires a human click with confirmation. This is by design: proposals can isolate production hosts and kill
  processes.
- **Never claim a decision.** Do not say "I approved it", "declined", or "done". When the user says "approve it",
  tell them to click Approve on that proposal in the view, or use "Open in Alert Zero" (`links.alertZero`) to
  decide in Kibana. Offer to explain it first.
- You can suggest a decline reason: duplicate, false positive, handled elsewhere, risk accepted, or other.
- After the user decides, call `get-alert-zero-proposal` to confirm the outcome (`decision`, `status`,
  `executionError`).

## "Mine" and assignment

Proposals have no owner. `scope: "mine"` matches proposals whose linked investigation lists the current user as
an assignee (`assignedToMe` on the card); `unassigned` matches investigations with no assignee. If `mine` is
empty, say so plainly and offer the full queue: "No proposals are on investigations assigned to you. There are
7 awaiting a decision in this space. Want to see them?" (`totalAwaitingDecision` is counted before the scope
filter.) If the result carries a `notice` (for example, the current user couldn't be identified), relay it instead
of claiming nothing is assigned to them.

## When Alert Zero is unavailable

If the review result's `status.available` is false, the proposal list is empty because Alert Zero can't be
reached, not because there is nothing to decide. Say that, and relay `status.reason` and `status.remediation`
verbatim. `check-alert-zero-status` returns the same fields.

| `state` | Meaning | Remediation |
|---------|---------|-------------|
| `plugin_disabled` | Alert Zero isn't installed or is switched off for this Kibana | Set `xpack.alertzero.enabled`, `xpack.proposals.enabled` and `xpack.agenticInvestigations.enabled` to true in kibana.yml and restart Kibana |
| `disabled_in_space` | Turned off in this space | Enable the `securitySolution:enableAlertZero` Advanced Setting (Stack Management → Advanced Settings) in that space |
| `space_not_found` | The requested space doesn't exist | Check the space id (Stack Management → Spaces), or omit `spaceId` to use the default space |
| `license` | Requires an Enterprise license | Upgrade to Enterprise or start a trial (Stack Management → License Management) |
| `serverless_tier` | Requires the Security Complete subscription | Upgrade the Serverless project to the Security Complete tier |
| `missing_privileges` | The API key's role can't use Alert Zero | Grant the Kibana feature privileges Alert Zero (read), Proposed Actions (read; all to approve/decline) and Agent Builder (read) |
| `dependencies_unavailable` | Enabled, but its dependencies are unavailable | Enable the agentBuilder, proposals and agenticInvestigations plugins, make sure Kibana service accounts are available, and restart Kibana |
| `unreachable` | Kibana couldn't be reached or returned an error | Check the Kibana URL, network, and credentials; the reason includes the error |

## Status glossary

| `status` | Meaning |
|----------|---------|
| `pending` | No decision yet; awaiting a human. Past `expiresAt` it can read `pending` briefly before settling as `expired` |
| `executing` | Approved; the action is running |
| `succeeded` | Approved; the action completed |
| `failed` | Approved; the action failed (`executionError` says why). Alert Zero may re-offer it as a new revision |
| `expired` | The deadline passed with no decision |
| `no_action` | A human answered and nothing ran: declined, or approved a proposal with no action |
| `superseded` | Replaced by a newer revision (`supersededBy`); only the latest revision can be decided |

`decision` is `approved` or `dismissed` (shown as Declined, with `dismissReason` and `rationale`). No `decision`
means nobody answered.

## Action glossary

Prefer the proposal's `action.reversible` when present; this table reflects the current defaults.

| `actionWorkflowId` | In plain English | Category | Reversible |
|--------------------|------------------|----------|------------|
| `system-alertzero-action-isolate-host` | Network-isolate the endpoint(s) via Elastic Defend | respond | Yes (release the host) |
| `system-alertzero-action-kill-process` | Terminate a process by PID or entity id, optionally with its descendants | respond | No |
| `system-alertzero-action-suspend-process` | Suspend a process by PID or entity id | respond | No |
| `system-alertzero-action-close-alerts-fp` | Close the listed alerts as false positives | investigate | Yes (alerts can be reopened) |
| `system-alertzero-action-handoff-to-forensics` | Hand an attack discovery to Forensics Watch for a deep investigation | investigate | No (commits a forensics run) |
| `system-alertzero-action-edit-rule` | Change fields on an existing detection rule | configure | Yes |
| `system-alertzero-action-add-rule-exception` | Add exception entries so a rule stops alerting on matching events | configure | Yes |
| `system-alertzero-action-create-rule` | Create a new detection rule (created disabled) | configure | Yes |
| `system-alertzero-action-enable-rule` | Turn on an existing detection rule | configure | Yes |
| `system-alertzero-action-install-prebuilt-rule` | Install an Elastic prebuilt rule at a specific version | configure | Yes |

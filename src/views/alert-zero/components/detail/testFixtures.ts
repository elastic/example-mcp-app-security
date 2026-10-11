/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Test data for the detail pane, modelled on payloads captured from a local
 * Kibana (Worker-driven investigation + a human follow-up chat round). The
 * proposal populates every `PROPOSAL_FIELD_KEYS` key, even where the
 * combination could not happen in practice, so each field's rendering is
 * exercised.
 */

import {
  ACTION_WORKFLOW_IDS,
  type AlertZeroInvestigation,
  type AlertZeroProposalDetail,
  type ConversationAttachment,
  type ProposalItem,
  type ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";

export const FULL_PROPOSAL: ProposalItem = {
  id: "prop-current-0002",
  spaceId: "soc-space",
  conversationId: "conv-1234",
  title: "Isolate host WIN-ANALYST01",
  comment:
    "This is a **confirmed** incident: Emotet and Qbot are running under jsmith.\n\n- Run-key persistence\n- C2 to `77.75.230.128`",
  actionWorkflowId: ACTION_WORKFLOW_IDS.isolateHost,
  actionInput: {
    comment: "Contain WIN-ANALYST01 while remediation proceeds",
    endpoint_ids: ["agent-5cdcd6f1d75392d9", "agent-1a05df104769c426"],
  },
  status: "failed",
  decision: "approved",
  supersededBy: "prop-next-0003",
  rootProposalId: "prop-root-0001",
  supersedes: "prop-root-0001",
  revision: 2,
  impact: "high",
  confidence: "medium",
  category: "respond",
  origin: "alertzero",
  expiresAt: "2099-01-01T12:00:00.000Z",
  decidedBy: { username: "dana", fullName: "Dana Analyst", email: "dana@example.com", profileUid: "u_dana" },
  decidedAt: "2026-10-09T13:00:00.000Z",
  dismissReason: "false_positive",
  rationale: "Rationale: approved after reviewing the Fleet status",
  executionError: "Endpoint agent offline (agent-1a05df104769c426)",
  previousExecutionError: "Timeout contacting Fleet server",
  workflowExecutionId: "wf-exec-7777",
  createdAt: "2026-10-09T12:59:49.247Z",
  createdBy: { username: "kibana/Test", fullName: "Worker Service", email: null },
  action: {
    name: "Isolate host",
    description: "Isolates Elastic Defend endpoints from the network.",
    category: "respond",
    impact: "high",
    reversible: true,
    approvalPolicy: "autonomy-dependent",
  },
  conversationTitle: "Phishing to Emotet/Qbot Infection Chain",
  conversationAgentId: "elastic-ai-agent",
  conversationAssignees: ["u_riley"],
  entityIds: ["host:host-win-analyst01", "user:jsmith@host-win-analyst01@local"],
};

function revision(id: string, rev: number, status: ProposalWithMetadata["status"]): ProposalWithMetadata {
  return {
    id,
    spaceId: "soc-space",
    conversationId: "conv-1234",
    title: `Isolate host (revision ${rev})`,
    comment: "Earlier revision",
    actionWorkflowId: ACTION_WORKFLOW_IDS.isolateHost,
    actionInput: { endpoint_ids: ["agent-5cdcd6f1d75392d9"] },
    status,
    impact: "high",
    confidence: "medium",
    origin: "alertzero",
    rootProposalId: "prop-root-0001",
    revision: rev,
    createdAt: "2026-10-09T12:00:00.000Z",
    action: { name: "Isolate host", category: "respond", reversible: true },
  };
}

export const SIBLING: ProposalWithMetadata = {
  id: "prop-sibling-0009",
  spaceId: "soc-space",
  conversationId: "conv-1234",
  title: "Kill process regsvr32.exe",
  comment: "Kill the dropper",
  actionWorkflowId: ACTION_WORKFLOW_IDS.killProcess,
  actionInput: { endpoint_ids: ["agent-5cdcd6f1d75392d9"], parameters: { pid: 2052 } },
  status: "pending",
  impact: "high",
  confidence: "high",
  origin: "alertzero",
  createdAt: "2026-10-09T12:59:50.000Z",
  action: { name: "Kill process", category: "respond", reversible: false },
};

/** Detail response; `futureField` stands in for a key the server adds later. */
export function makeDetail(): AlertZeroProposalDetail {
  const proposal = { ...FULL_PROPOSAL, futureField: "from-the-future" } as AlertZeroProposalDetail["proposal"];
  return {
    proposal,
    revisionChain: [revision("prop-root-0001", 1, "superseded"), FULL_PROPOSAL, revision("prop-next-0003", 3, "pending")],
    siblings: [SIBLING],
    links: {
      alertZero: "http://kibana.test/s/soc-space/app/alertzero?selectedConversationId=conv-1234",
      agentBuilder: "http://kibana.test/s/soc-space/app/agent_builder/agents/elastic-ai-agent/conversations/conv-1234",
    },
    kibanaUrl: "http://kibana.test",
    spaceId: "soc-space",
    canDecide: true,
  };
}

function attachment(
  id: string,
  type: string,
  data: unknown,
  extra: Partial<ConversationAttachment> = {},
): ConversationAttachment {
  return {
    id,
    type,
    current_version: 1,
    active: true,
    versions: [{ version: 1, data, created_at: "2026-10-09T12:37:00.000Z" }],
    ...extra,
  };
}

const ROUND_START = "2026-10-09T14:00:00.000Z";
const WORKER = {
  type: "user",
  id: 'realm:["_service_account","_service_account","kibana/Test"]',
  username: "kibana/Test",
};

export function makeInvestigation(): AlertZeroInvestigation {
  return {
    conversation: {
      id: "conv-1234",
      agent_id: "elastic-ai-agent",
      user: { username: "kibana/Test" },
      title: "Phishing to Emotet/Qbot Infection Chain",
      created_at: "2026-10-09T12:36:54.344Z",
      updated_at: "2026-10-09T14:00:09.000Z",
      template_id: "investigation",
      template_version: 2,
      read_only: false,
      access_control: { access_mode: "public", entries: [] },
      metadata: {
        status: "open",
        severity: "critical",
        assignees: ["u_riley"],
        summary: "Excel phishing led to Emotet and Qbot on WIN-ANALYST01.",
        description: "Attack Discovery review covering 11 detection alerts.",
        verdict: "Handed off to Forensics Watch, approved by the worker.",
        workflow_execution_ids: ["wf-run-aaaa"],
        custom_meta: "meta-extra-value",
      },
      rounds: [
        {
          id: "round-1",
          status: "completed",
          started_at: ROUND_START,
          author: { id: "u_riley", username: "riley" },
          input: {
            message: "What should I do next?",
            attachment_refs: [{ attachment_id: "attack-discovery", version: 1, operation: "read" }],
          },
          steps: [
            { type: "relevant_skills", skills: [{ id: "proposal-management", name: "proposal-management", description: "Read proposals" }] },
            { type: "reasoning", reasoning: "Let me pull the alerts first." },
            {
              type: "tool_call",
              tool_call_id: "tc-1",
              tool_id: "platform.core.execute_esql",
              params: { query: "FROM alerts" },
              results: [
                {
                  tool_result_id: "r1",
                  type: "esql_results",
                  data: {
                    query: "FROM alerts | LIMIT 2",
                    columns: [
                      { name: "host.name", type: "keyword" },
                      { name: "count", type: "long" },
                    ],
                    values: [
                      ["WIN-ANALYST01", 11],
                      ["SRV-FILE", 2],
                    ],
                  },
                },
              ],
            },
            {
              type: "tool_call",
              tool_call_id: "tc-2",
              tool_id: "read_file",
              params: { path: "/tool_calls/missing.json" },
              results: [{ tool_result_id: "r2", type: "error", data: { message: "ENOENT: no such file" } }],
            },
            {
              type: "tool_call",
              tool_call_id: "tc-3",
              tool_id: "attachments.read",
              params: { attachment_id: "analysis-verdict" },
              results: [{ tool_result_id: "r3", type: "other", data: { payload: "other-result-payload" } }],
            },
          ],
          response: {
            message: 'Here is the decision waiting on you.\n\n<render_attachment id="att-proposal-current" />\n\nApprove it soon.',
          },
          model_usage: { llm_calls: 3, input_tokens: 80476, output_tokens: 3984, model: "claude-test" },
          time_to_first_token: 3000,
          time_to_last_token: 9000,
          trace_id: "trace-round-1",
        },
      ],
      events: [
        {
          id: "ev-1",
          type: "user_message",
          created_at: "2026-10-09T12:36:55.222Z",
          actor: WORKER,
          data: { message: 'Review started for "Phishing to Emotet/Qbot Infection Chain".', attachment_refs: [] },
        },
        {
          id: "ev-2",
          type: "attachment_added",
          created_at: "2026-10-09T12:36:58.312Z",
          actor: { type: "user", id: "unknown" },
          data: { attachment_id: "attack-discovery", attachment_type: "security.attack_discovery", current_version: 1, render_inline: true, source: "workflow" },
        },
        {
          id: "ev-3",
          type: "attachment_added",
          created_at: "2026-10-09T12:36:59.369Z",
          actor: { type: "user", id: "unknown" },
          data: { attachment_id: "correlated-alerts-0", attachment_type: "security.alerts", current_version: 1, source: "workflow" },
        },
        {
          id: "ev-4",
          type: "attachment_added",
          created_at: "2026-10-09T12:59:50.262Z",
          actor: { type: "user", id: "unknown" },
          data: { attachment_id: "att-proposal-current", attachment_type: "platform.proposal", current_version: 1, source: "server_api" },
        },
        {
          id: "ev-5",
          type: "execution_failed",
          created_at: "2026-10-09T13:10:00.000Z",
          actor: { type: "agent", id: "elastic-ai-agent" },
          data: {
            trace_id: "trace-other",
            error: { code: "agentExecutionError", message: "Inference stream exceeded the maximum allowed duration" },
          },
        },
        {
          id: "ev-6",
          type: "prompt_response",
          created_at: "2026-10-09T13:20:00.000Z",
          actor: { type: "user", id: "u_riley", username: "riley" },
          data: { prompt_id: "prompt-1", response: "Prompt answer text" },
        },
        {
          id: "ev-7",
          type: "some_future_event",
          created_at: "2026-10-09T13:30:00.000Z",
          data: { foo: "bar-future" },
        },
        {
          id: "ev-8",
          type: "user_message",
          created_at: ROUND_START,
          actor: { type: "user", id: "u_riley", username: "riley" },
          data: { message: "What should I do next?", attachment_refs: [] },
        },
        {
          id: "ev-9",
          type: "execution_started",
          created_at: "2026-10-09T14:00:00.300Z",
          actor: { type: "agent", id: "elastic-ai-agent" },
          data: { trigger_type: "user_message" },
        },
        {
          id: "ev-10",
          type: "execution_step",
          created_at: ROUND_START,
          actor: { type: "agent", id: "elastic-ai-agent" },
          data: { step: { type: "tool_call", tool_call_id: "tc-1", tool_id: "platform.core.execute_esql" }, sequence: 2 },
        },
        {
          id: "ev-11",
          type: "execution_terminated",
          created_at: "2026-10-09T14:00:09.000Z",
          actor: { type: "agent", id: "elastic-ai-agent" },
          data: { trace_id: "trace-round-1", model_usage: { llm_calls: 3 } },
        },
      ],
      attachments: [
        attachment(
          "attack-discovery",
          "security.attack_discovery",
          {
            id: "ad-96d38506",
            title: "Phishing to Emotet/Qbot Infection Chain",
            timestamp: "2026-10-09T12:36:49.275Z",
            alert_ids: ["alert-1", "alert-2"],
            mitre_attack_tactics: ["Initial Access", "Execution"],
            summary_markdown: "Excel phishing led to regsvr32 proxy execution.",
            entity_summary_markdown: "Infection on {{ host.name f2011eed-3026 }} as {{ user.name 22316124-2d9a }}.",
            details_markdown: "- {{ process.name regsvr32.exe }} spawned by EXCEL.EXE",
            replacements: { "f2011eed-3026": "WIN-ANALYST01", "22316124-2d9a": "jsmith" },
          },
          { description: "The Attack Discovery under review", origin: "ad-96d38506", readonly: true },
        ),
        attachment("correlated-alerts-0", "security.alerts", { alertIds: ["alert-1", "alert-2", "alert-3"] }, {
          description: "Detection alerts correlated by this Attack Discovery (batch 1 of 1)",
        }),
        attachment(
          "impact-1",
          "investigation_impact",
          {
            id: "impact-1",
            summary: "Two entities affected.",
            entities: [
              { id: "host:host-win-analyst01", name: "WIN-ANALYST01", type: "host" },
              { id: "user:jsmith@host-win-analyst01@local", name: "jsmith@WIN-ANALYST01", type: "user" },
            ],
            createdAt: "2026-10-09T12:37:03.896Z",
            updatedAt: "2026-10-09T12:37:03.896Z",
          },
          { hidden: true },
        ),
        attachment(
          "analysis-verdict",
          "security.attack_discovery.verdict",
          {
            verdict: "true_positive",
            summary_markdown: "This discovery holds up as a true positive.",
            rationale_markdown: "- **alert_linkage** — completed, supports the chain",
          },
          { description: "FP/TP analysis verdict and summary" },
        ),
        attachment("att-proposal-current", "platform.proposal", { proposalId: "prop-current-0002", title: "Isolate host" }, { origin: "prop-current-0002" }),
        attachment("att-proposal-sibling", "platform.proposal", { proposalId: "prop-sibling-0009", title: "Kill process" }, { origin: "prop-sibling-0009" }),
        attachment(
          "forensic-timeline",
          "security.investigation.timeline",
          { events: [{ timestamp: "2026-10-07T05:01:16.609Z", host: "WIN-ANALYST01", description: "EXCEL.EXE spawns regsvr32.exe" }] },
          { description: "Attack timeline: WIN-ANALYST01" },
        ),
        attachment(
          "forensic-iocs",
          "security.investigation.iocs",
          {
            shas: [{ value: "bb444759e8d9a1a9", comment: "Emotet DLL" }],
            ips: [{ value: "77.75.230.128", comment: "C2 server, fetched 19825.dat" }],
            file_paths: [],
            malicious_commands: [{ value: "regsvr32.exe /S ..\\oxnv1.ooccxx" }],
            compromised_identities: [{ value: "jsmith" }],
            affected_hosts: [{ value: "WIN-ANALYST01", comment: "patient zero" }],
          },
          { description: "Extracted indicators of compromise" },
        ),
        attachment("hypotheses-1", "investigation_hypotheses", {
          hypotheses: [
            {
              candidate: "Phishing macro dropper",
              confidence: 0.8,
              status: "confirmed",
              reason: "Macro spawned regsvr32",
              evidence: [{ description: "EXCEL.EXE was the parent process" }],
            },
          ],
        }),
        attachment("rule-1", "security.rule", { name: "Emotet Rule Name", rule_id: "rule-abc", severity: "high", query: "process where true" }),
        attachment("threat-1", "security.threat", { report_id: "report-42", title: "Qbot campaign report", severity: "high", source: "Elastic Labs" }),
        attachment("esql-1", "esql", { query: 'FROM logs-* | WHERE host.name == "WIN-ANALYST01"', description: "Hunt query" }),
        attachment("note-1", "text", { content: "Analyst note: double-check backups" }),
        attachment("future-1", "custom.future_type", { mystery_key: "mystery-value" }),
        attachment("removed-note", "text", { content: "Removed note content" }, { active: false }),
        {
          id: "draft-note",
          type: "text",
          current_version: 2,
          active: true,
          versions: [
            { version: 1, data: { content: "First draft note" }, created_at: "2026-10-09T12:40:00.000Z" },
            { version: 2, data: { content: "Second draft note" }, created_at: "2026-10-09T12:41:00.000Z" },
          ],
        },
      ],
    },
    assignees: [{ uid: "u_riley", fullName: "Riley Responder", username: "riley" }],
    alerts: {
      "alert-1": {
        id: "alert-1",
        ruleName: "Emotet Malware Detected",
        severity: "critical",
        riskScore: 99,
        host: "WIN-ANALYST01",
        user: "jsmith",
        timestamp: "2026-10-07T05:01:16.609Z",
        reason: "malware event on WIN-ANALYST01",
        workflowStatus: "open",
      },
      "alert-2": { id: "alert-2", ruleName: "Suspicious Regsvr32 Execution", severity: "high" },
    },
    links: {
      alertZero: "http://kibana.test/s/soc-space/app/alertzero?selectedConversationId=conv-1234",
      agentBuilder: "http://kibana.test/s/soc-space/app/agent_builder/conversations/conv-1234",
    },
  };
}

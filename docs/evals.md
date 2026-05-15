# Eval Harness

LLM-powered evals for the Elastic Security MCP app's skill layer. The harness
tests whether the LLM host activates the right skill, calls the right tools in
the right order, and does not fire on unrelated queries.

Regular `npm test` never touches this harness — it only runs when
`RUN_LLM_EVALS=1` is set, so CI stays fast and free of LLM costs.

---

## Architecture

```
Dataset (examples)
   │
   ▼
runner.ts ─ describe.skipIf(!RUN_LLM_EVALS)(dataset.name, () => {
   │            for each example:
   │               trajectory = await runMcpHostLoop(input)
   │               scores     = await evaluators[*](trajectory, expected)
   │               assert score >= passingScore
   │            afterAll: print Markdown table to stdout
   │         })
   │
   ├── runMcpHostLoop(input)
   │      InMemoryTransport ─ Client ─ McpServer
   │      LLM provider (Anthropic / OpenAI / LiteLLM)
   │      loop ≤ MAX_TURNS=8: LLM → tool calls → results → repeat
   │      returns Trajectory (ordered ToolCall[])
   │
   └── Evaluators
          skill-activation    binary: was skill tool called?
          negative-activation binary: was skill tool correctly absent?
          tool-selection      F1 precision/recall against expected.tools
          trajectory          LCS similarity of actual vs expected sequence
          criteria            LLM-as-judge against natural-language assertions
```

### Key design choices

| Decision | Rationale |
|---|---|
| In-process via `InMemoryTransport` | No network, no server process — evals run anywhere |
| `describe.skipIf(!RUN_LLM_EVALS)` | Zero LLM cost in regular `npm test` |
| `Evaluator` is a plain function | Easy to compose; factory pattern for stateful evaluators (criteria) |
| `'N/A'` return instead of 0 | Datasets omit irrelevant evaluator dimensions without masking real regressions |
| LCS for trajectory | Order matters; set-based coverage is tool-selection's job |

---

## Dataset shape

A dataset is a `Dataset` object exported from a `*.dataset.ts` file:

```typescript
import type { Dataset } from "../types.js";

export const myDataset: Dataset = {
  name: "my-skill",
  examples: [
    {
      id: "ms-pos-01",                    // stable, unique — appears in CI summaries
      input: "user message to the LLM",   // the query sent to runMcpHostLoop
      expected: {
        skill: "entry-point-tool-name",   // tool the skill SKILL.md instructs the LLM to call
        tools: ["entry-point-tool-name"], // ordered list for trajectory/tool-selection
        criteria: [                       // natural-language assertions for LLM-as-judge
          "The model called the correct entry-point tool",
        ],
      },
    },
  ],
};
```

All three `expected` fields are **optional**:

| Field | Evaluators that use it | Omit when… |
|---|---|---|
| `skill` | `skill-activation`, `negative-activation` | Dataset doesn't test skill routing |
| `tools` | `tool-selection`, `trajectory` | No ordered tool expectation |
| `criteria` | `criteria` | No LLM-as-judge needed (saves cost) |

Omitting a field causes the evaluator to return `'N/A'` for that example rather than a false 0.

### Positive vs distractor examples

A **positive** example is a query that *should* activate the skill.  
A **distractor** example is an unrelated query that *should not*.

Use separate `runDataset` calls with different evaluators for each group:

```typescript
// Positive: skill should fire
runDataset(
  { name: "my-skill: positives", examples: positiveExamples },
  { "skill-activation": skillActivation, "tool-selection": toolSelection },
  { passingScore: 0.8 }
);

// Distractor: skill must NOT fire (gate is 100%)
runDataset(
  { name: "my-skill: distractors", examples: distractorExamples },
  { "negative-activation": negativeActivation },
  { passingScore: 1.0 }
);
```

---

## Evaluator catalog

### `skill-activation`

**Type**: binary · **Score**: `1` if `expected.skill` found in trajectory, `0` otherwise  
**Returns `'N/A'`**: when `expected.skill` is absent  
**Gate**: ≥ 0.8 on positive examples (use `passingScore: 0.8`)

Tests whether the LLM called the skill's model-facing entry-point tool at
least once.

### `negative-activation`

**Type**: binary · **Score**: `1` if `expected.skill` is *absent* from trajectory, `0` if present  
**Returns `'N/A'`**: when `expected.skill` is absent  
**Gate**: 1.0 on distractor examples (use `passingScore: 1.0`)

Tests that the skill does not over-trigger on unrelated queries. Any false
positive here means the skill's SKILL.md is too broad.

### `tool-selection`

**Type**: F1 · **Score**: harmonic mean of precision and recall against `expected.tools` (set-based)  
**Returns `'N/A'`**: when `expected.tools` is absent  
**Gate**: ≥ 0.8 on positive examples

Tests *which* tools were called, ignoring order. Missed tools lower recall;
spurious tools lower precision. Failure reason includes `missed: [...]` and
`extra: [...]`.

### `trajectory`

**Type**: LCS similarity · **Score**: `lcs(actual, expected) / max(|actual|, |expected|)`  
**Returns `'N/A'`**: when `expected.tools` is absent  
**Gate**: ≥ 0.7 on positive examples (sequence matching is looser than set matching)

Tests *order*. Dividing by `max` penalises both missing and extra steps.
Use alongside `tool-selection` for full coverage.

### `criteria`

**Type**: LLM-as-judge · **Score**: `0.0–1.0` parsed from a rubric prompt response  
**Returns `'N/A'`**: when `expected.criteria` is absent  
**Gate**: ≥ 0.7

Calls the judge LLM with the trajectory `{tool, args}` pairs and the
criteria list. Asks for `{"score": <0–1>, "reasoning": "..."}`. Falls back
to regex number extraction if JSON parse fails. Use for semantic assertions
that structural evaluators can't express.

**Cost**: one extra LLM call per example. Omit `expected.criteria` to skip.

---

## How to add a dataset

1. **Create the data file** `evals/datasets/<skill-name>.dataset.ts`:

   ```typescript
   import type { Dataset, Example } from "../types.js";

   const SKILL_TOOL = "my-tool"; // the model-facing entry-point tool

   export const positiveExamples: Example[] = [
     { id: "ms-pos-01", input: "...", expected: { skill: SKILL_TOOL, tools: [SKILL_TOOL] } },
     // add ≥ 4 examples
   ];

   export const distractorExamples: Example[] = [
     { id: "ms-neg-01", input: "...", expected: { skill: SKILL_TOOL } },
     // add ≥ 4 examples
   ];

   export const myDataset: Dataset = {
     name: "<skill-name>",
     examples: [...positiveExamples, ...distractorExamples],
   };
   ```

2. **Create the eval spec** `evals/<skill-name>.eval.test.ts`:

   ```typescript
   import { runDataset } from "./runner.js";
   import { positiveExamples, distractorExamples } from "./datasets/<skill-name>.dataset.js";
   import { skillActivation } from "./evaluators/skill-activation.js";
   import { negativeActivation } from "./evaluators/negative-activation.js";
   import { toolSelection } from "./evaluators/tool-selection.js";

   runDataset(
     { name: "<skill-name>: positives", examples: positiveExamples },
     { "skill-activation": skillActivation, "tool-selection": toolSelection },
     { passingScore: 0.8 }
   );

   runDataset(
     { name: "<skill-name>: distractors", examples: distractorExamples },
     { "negative-activation": negativeActivation },
     { passingScore: 1.0 }
   );
   ```

3. **Run locally**:

   ```bash
   # Anthropic (preferred)
   ANTHROPIC_API_KEY=sk-ant-... npm run test:evals

   # OpenAI / LiteLLM proxy
   OPENAI_API_KEY=sk-... LITELLM_BASE_URL=https://... npm run test:evals

   # Local Ollama (zero-cost smoke run; tool-calling quality varies by model)
   OPENAI_API_KEY=ollama \
     LITELLM_BASE_URL=http://localhost:11434/v1 \
     OPENAI_MODEL=qwen2.5:32b-instruct-q4_K_M \
     npm run test:evals
   ```

   `createEvalServer` stubs all Elastic-cluster calls, so no `CLUSTERS_JSON`
   is needed when running skill-routing evaluators (`skill-activation`,
   `tool-selection`, `negative-activation`, `trajectory`, `criteria`).

4. **Trigger in CI**: open a PR and add the `evals` label (requires write access).

---

## CI gating

### Workflow: `.github/workflows/evals.yml`

| Trigger | When |
|---|---|
| `workflow_dispatch` | Manual run from Actions UI |
| `schedule` | Nightly at 02:00 UTC |
| `pull_request_target` | When `evals` label is added to a PR |

The concurrency group `evals-<ref>` cancels superseded runs to avoid wasting
LLM quota on stale pushes.

### Required secrets

| Secret | Purpose |
|---|---|
| `EVAL_ANTHROPIC_API_KEY` | Anthropic API key (priority provider) |
| `EVAL_OPENAI_API_KEY` | OpenAI / LiteLLM API key (fallback) |
| `EVAL_LITELLM_BASE_URL` | Optional LiteLLM proxy base URL |
| `EVAL_CLUSTERS_JSON` | Elastic cluster credentials for the MCP server |

### Passing thresholds (recommended defaults)

| Evaluator | Positives | Distractors |
|---|---|---|
| `skill-activation` | ≥ 0.8 | — |
| `negative-activation` | — | = 1.0 |
| `tool-selection` | ≥ 0.8 | — |
| `trajectory` | ≥ 0.7 | — |
| `criteria` | ≥ 0.7 | — |

Results are posted as a Markdown table to the GitHub Actions job summary
(`$GITHUB_STEP_SUMMARY`) after every run.

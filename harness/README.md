# Harness — Storybook-like preview for the views

Run the six MCP app views against canned fixtures in a plain Vite dev server.
No MCP server, no Claude Desktop, no postMessage handshake — just React +
CSS with hot-reload.

## Start it

```bash
npm run harness
```

Opens `http://localhost:5370/harness/` — a catalogue page with each view
embedded in an iframe. Edit anything under `src/views/**` or
`harness/fixtures/**` and the page hot-reloads.

## How it works

- `vite.harness.config.ts` serves the repo root and aliases
  `@modelcontextprotocol/ext-apps` → `harness/mock-ext-apps.ts`.
- The shim re-exports an `App` class with the same surface the views use
  (`connect`, `callServerTool`, `sendMessage`, `onhostcontextchanged`, …) but
  resolves every tool call against a per-view fixture map instead of going
  over the real transport.
- The active view is detected from the URL path — a view loaded at
  `/src/views/alert-triage/mcp-app.html` gets `harness/fixtures/alert-triage.ts`.

## Fixtures

Each file at `harness/fixtures/<view>.ts` exports:

```ts
export default {
  "tool-name": <data | (args) => data>,
  // ...
};

// Optional named variants (switchable via ?fixture=NAME or the tile chip):
export const variants = {
  empty: { "tool-name": [] },
};
```

The shim wraps whatever you return in the MCP text-content shape
`{ content: [{ type: "text", text: JSON.stringify(data) }] }`, so you just
return the raw JSON object the view expects.

Current views + their tool maps:

| View              | Fixture file                          | Tools stubbed |
|-------------------|---------------------------------------|---------------|
| alert-triage      | `harness/fixtures/alert-triage.ts`    | `poll-alerts`, `get-alert-context`, `acknowledge-alert`, `create-case`, `attach-alert-to-case` |
| case-management   | `harness/fixtures/case-management.ts` | `list-cases`, `get-case`, `get-case-alerts`, `get-case-comments`, `create-case`, `update-case` |
| detection-rules   | `harness/fixtures/detection-rules.ts` | `find-rules`, `get-rule`, `toggle-rule`, `validate-query`, `noisy-rules` |
| attack-discovery  | `harness/fixtures/attack-discovery.ts`| `get-generation-status`, `list-ai-connectors`, `poll-discoveries`, `assess-discovery-confidence`, `enrich-discovery`, `approve-discoveries`, `acknowledge-discoveries` |
| sample-data       | `harness/fixtures/sample-data.ts`     | `check-existing-sample-data`, `create-rules-for-scenario`, `generate-scenario`, `cleanup-sample-data` |
| threat-hunt       | `harness/fixtures/threat-hunt.ts`     | `execute-esql`, `investigate-entity`, `get-entity-detail` |

## Controls

- **Theme toggle** — press `T` inside any view (or set `?theme=light`).
- **Latency** — add `?latency=500` to the view URL (default 120ms).
- **Variant** — add `?fixture=empty` (or whatever variants your fixture exports),
  or pick the chip on the tile header.

## Notes for designers

- CSS, TSX, and fixture edits hot-reload on save. **No server restart needed.**
- Styles live at `src/views/<view>/styles.css`.
- Shared design-system variables & utility classes live at
  `src/shared/theme.ts` (injected at runtime).
- A small `harness · <slug> · dark (press T)` chip sits in the bottom-right of
  every previewed view so you know you're in the harness, not the real MCP host.

## Not in scope

- Server-side code under `src/tools/**` is **not** loaded by the harness. Only
  the view code runs. If you need a new tool shape, add it to the fixture for
  that view.
- The harness is dev-only. Production builds (`npm run build`) are unchanged
  and still use `vite.config.ts`.

# Security MCP App - Initial Meeting

**Date:** April 14, 2026
**Lead:** Nir Oren
**Type:** Initial meeting - short, concrete, decisions-oriented

---

## Agenda

| # | Topic | Time |
|---|-------|------|
| 1 | Where we are today (POC state) | 3 min |
| 2 | Short-term: shipping v0.1.0 experimental ASAP | 10 min |
| 3 | Near-term future: product roadmap & team | 7 min |
| 4 | Open questions & decisions needed | 5 min |

---

## 1. Where We Are Today

The POC (v0.1.0) built by James Spiteri is functional and impressive in scope:

- **6 interactive UIs**: Alert Triage, Attack Discovery, Case Management, Detection Rules, Threat Hunt, Sample Data
- **42 MCP tools** (6 model-facing + ~36 app-only)
- **Dual transport**: stdio (local) and HTTP (remote)
- **Stack**: React 19, Tailwind 4, Vite 8, TypeScript 6, MCP SDK 1.27
- Works with Claude Desktop, VS Code, and Claude.ai (via tunnel)

**Bottom line:** The architecture is sound. The gap is between "works as a demo" and "ships as a product."

---

## 2. Short-Term: Shipping v0.1.0 Experimental ASAP

### Key Decisions Already Made

- **v0.1.0 ships under an "experimental" label** - sets expectations: functional, intentional, not yet production-grade
- **Local MCP only** (stdio) - no remote/web support in v0.1.0. This is a deliberate scope constraint
  - Implication: ChatGPT and web-based MCP clients are out of scope by design

### Key Decision Making for First Version

These are the blockers - decisions that gate everything else:

| # | What | Why | How |
|---|------|-----|-----|
| 1 | **Distribution & packaging strategy** | Easy process, one-click install, bring users in as quickly as possible | Three options to research and decide: 1) Claude Plugin, 2) `modelcontextprotocol/ext-apps` deployment, 3) hand-made install script |
| 2 | **Product scope / feature set for v0.1.0** | Scope alignment | Which of the 6 capabilities ship in v0.1.0? e.g. is sample data generation part of the first version, or do we trim to core SOC workflows only? |
| 3 | **UX/UI decision for v0.1.0** | Do we want to have an Elastic UI touch? | TBD |

### Should-Do for Quality (P1)

Engineering gaps that make the difference between "experimental" and "embarrassing":

| # | What | Why | Size |
|---|------|-----|------|
| 1 | Fix bulk NDJSON bug | Sample data generator broken - wrong content type for `/_bulk` | Small |
| 2 | Add request timeouts | No timeout on ES/Kibana calls - a hung cluster freezes everything | Small |
| 3 | Input validation | Several tools crash on malformed JSON input | Small |
| 4 | Fix silent failures | `safe*` helpers swallow errors - users see blank panels, no error message | Medium |
| 5 | Add `zod` as direct dependency | Used in all 42 schemas but only a transitive dep - SDK upgrade could break build | Trivial |
| 6 | Tool visibility audit | Some app-only tools may be leaking to the LLM, wasting token budget | Small |
| 7 | Standardize error handling (consistent error response format) | Medium |
| 8 | Add structured logging (for diagnosability) | Medium |

### Code Quality (P2)

| # | What | Size |
|---|------|------|
| 9 | Graceful shutdown (SIGTERM handling) | Small |
| 10 | Retry logic for transient ES failures (429, 503) | Small |
| 11 | Optimize model-facing tool descriptions (token budget) | Small |

### Timeline Estimate

**~2-3 weeks for one developer** to ship v0.1.0 local-only experimental (after P0 decisions are locked).

---

## 3. Near-Term Future: Product Roadmap & Team

### What Comes After v0.1.0

**Quality & reliability hardening:**

- Automated tests, CI pipeline, caching, health diagnostic tool, changelog/contributing guide

**Refactoring consideration:**

- Evaluate refactoring with `modelcontextprotocol/ext-apps` standard - the official way to build interactive MCP UIs. Multi-agent by design (works across Claude, ChatGPT, VS Code, Goose, etc.). This could become the foundation for broader agent compatibility.

**Remote support (v0.2.0+):**

- HTTP/remote support enabling Claude.ai, shared deployments, and broader agent compatibility
- Auth middleware, CORS, rate limiting, TLS
- Containerization, cloud hosting, CI/CD, monitoring
- Roughly triples the scope vs. local-only

### Product & Feature Direction

Open questions that need alignment:

- **Which agents do we officially support?** Claude Desktop and VS Code are natural. What about others?
- **Feature prioritization post v0.1.0:** remote support, more integrations, more security workflows?
- **ext-apps alignment:** do we adopt `modelcontextprotocol/ext-apps` as the UI standard going forward?

### Team & Ownership

- **PM assignment** - who owns the product direction and backlog?
- **Engineering team** - Contextual Security Apps team responsibility. Start small and scale according to product scope

---

## 4. Open Questions & Decisions Needed

These need answers to move forward:

| # | Question | Impact |
|---|----------|--------|
| 1 | **Who is the PM?** | Blocks backlog prioritization and stakeholder alignment |
| 2 | **Distribution strategy?** Claude Plugin vs. ext-apps vs. hand-made script | Blocks the entire shipping story |
| 3 | **v0.1.0 feature scope?** Which of the 6 capabilities make the cut? | Determines effort and timeline |
| 4 | **UX/UI approach for v0.1.0?** Full React UIs, simplified, or text-only? | Major scope lever |
| 5 | **v0.1.0 agent support list** - just Claude Desktop + VS Code, or more? | Scopes deployment and testing work |
| 6 | **v0.1.0 target date?** 2-3 weeks from when? | Needs commitment to start the clock |

---

## Recommended Next Steps

1. **Lock the P0 decisions** - distribution strategy, feature scope, UX/UI approach
2. **Assign PM**
3. **Set a v0.1.0 target date** (propose: 2-3 weeks after P0 decisions are locked)
4. **Nir starts on P1 engineering fixes** in parallel with P0 decision-making
5. **Schedule a follow-up** for near-term roadmap once v0.1.0 is out the door

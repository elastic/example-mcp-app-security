# Elastic Security MCP App: POC-to-Beta Gap Analysis

> Comprehensive gap analysis of the Elastic Security MCP App (v0.1.0 POC) against production/beta readiness standards.
>
> **Sources**: MCP Apps spec, fastmcp best practices, and multiple production deployment guides.
>
> **Date**: April 2026

## Current State Summary

The project is a well-built POC with impressive feature coverage:

- 6 interactive React UIs (alert triage, attack discovery, cases, rules, threat hunt, sample data)
- 42 registered MCP tools (6 model-facing + ~36 app-only)
- Dual transport: stdio (Claude Desktop / VS Code) and HTTP (remote / tunnel)
- Elastic Stack integration via direct REST (Elasticsearch + Kibana APIs)
- Modern stack: React 19, Tailwind 4, Vite 8, TypeScript 6, MCP SDK 1.27

The architecture is sound for a POC. Below are the gaps organized by severity across two deployment scenarios.

---

## Version 1: Local-Only Beta (stdio / Claude Desktop + VS Code)

The stdio transport provides process isolation by the OS — only the parent app (Claude Desktop / VS Code) can communicate with the server. This eliminates an entire class of security concerns and removes the need for cloud infrastructure.

### P0 — Must Fix

| # | Gap | Why It Matters | Effort |
|---|-----|----------------|--------|
| 1 | **Bulk NDJSON bug** | `esRequest` in `src/elastic/client.ts` uses `Content-Type: application/json` and `JSON.stringify` for all requests including `/_bulk`, which expects NDJSON with `application/x-ndjson`. Sample data generator likely broken. | Small |
| 2 | **No request timeouts** | `fetch()` calls to ES/Kibana have no timeout. A hung cluster connection freezes the MCP server and Claude's UI indefinitely. Fix: `AbortController` with ~30s timeout on all `fetch()` calls. | Small |
| 3 | **Input validation gaps** | Several tools `JSON.parse` raw strings from the UI (`alert`, `discoveries`, `rule`, `updates`, `filter`) without try/catch. Malformed input becomes an uncaught runtime error. | Small |
| 4 | **Silent `safe*` failures** | `safeEsql`, `safeQuery`, `safeSearch` return `null` or `[]` on failure. Hides cluster permission errors, mapping issues, and connectivity problems. Users see blank panels with no indication anything went wrong. | Medium |
| 5 | **Missing `zod` direct dependency** | Zod is used extensively in all 42 tool schemas but is only a transitive dependency via `@modelcontextprotocol/sdk`. An SDK upgrade could break resolution. | Trivial |
| 6 | **Tool visibility audit** | Some tools (`acknowledge-alerts-bulk`, `list-ai-connectors`, `create-case`) may lack `visibility: ["app"]`. They'd appear in the LLM's tool list, wasting token budget and confusing the model. | Small |

### P1 — Should Fix

| # | Gap | Why It Matters | Effort |
|---|-----|----------------|--------|
| 7 | **Inconsistent error handling** | Some tools try/catch and return `{ error: ... }`, others propagate exceptions, some use empty `catch` blocks. No standard error response format. | Medium |
| 8 | **No structured logging** | Only sparse `console.error` in a few places. No structured format, no log levels, no correlation IDs. When something fails, there's no way to diagnose it. | Medium |
| 9 | **No graceful shutdown** | No SIGTERM/SIGINT handling. In-flight requests are dropped on process termination. Claude Desktop may show a confusing error on restart. | Small |
| 10 | **No retry logic** | No retries for transient ES/Kibana failures (429 rate limits, 502, 503, 504). Causes immediate tool failures instead of recovering. | Small |
| 11 | **Tool description token optimization** | Even with app-only visibility on most tools, the 6–7 model-facing tools should have tight, optimized descriptions per fastmcp best practices (token budget is the hardest constraint). | Small |

### P2 — Nice to Have for Beta

| # | Gap | Why It Matters | Effort |
|---|-----|----------------|--------|
| 12 | **Zero automated tests** | No test files, no test framework. Regressions caught only by `tsc --noEmit`. | Large |
| 13 | **No CI pipeline** | No `.github/workflows/`. No automated typecheck/lint/test on PRs. | Medium |
| 14 | **No caching** | Repeated calls to slow-changing data (index mappings, connector lists, rule lists) always hit ES. | Medium |
| 15 | **No health/diagnostic tool** | No way for users to verify their ES/Kibana connection is working before they start using tools. | Small |
| 16 | **No changelog / contributing guide** | External beta users need onboarding docs, contribution instructions, and change tracking. | Small |

### What You DON'T Need for Local-Only

- No auth middleware (stdio is process-isolated)
- No CORS configuration (no HTTP)
- No rate limiting (single user, single process)
- No Dockerfile or cloud deployment
- No TLS
- No multitenancy or session management
- No custom MCP connector setup

### Estimated Effort: ~2–3 weeks for one developer

---

## Version 2: Remote Beta (adds HTTP / Claude.ai / shared deployment)

Everything from Version 1 **plus** the following. All items are additive — they don't exist in the local-only version.

### P0 — Must Fix (additive)

| # | Gap | Why It Matters | Effort |
|---|-----|----------------|--------|
| 17 | **Auth middleware on `/mcp`** | `POST /mcp` in `main.ts` has zero authentication. Anyone reaching the URL gets full proxy access to your Elastic cluster with the server's API keys. This is the single biggest risk. | Medium |
| 18 | **CORS restriction** | `cors()` is called with no configuration, allowing all origins. Must restrict to known hosts (`claude.ai`, your domain, `localhost` for dev). | Trivial |
| 19 | **Rate limiting** | Without it, a single client (or attacker) can spam your ES cluster through the open endpoint. | Small |
| 20 | **TLS termination plan** | The server is HTTP-only. Claude.ai custom connectors require HTTPS. Need TLS via reverse proxy or cloud-managed certificate. | Medium |
| 21 | **Dockerfile (multi-stage)** | No containerization means no reproducible deployment. Build stage (compile TS + bundle views) + slim runtime stage, non-root user, proper signal handling. | Medium |
| 22 | **McpServer instance reuse** | `main.ts` creates a new `McpServer` per HTTP request, re-registering all 42 tools every time. Must be a singleton. | Small |

### P1 — Should Fix (additive)

| # | Gap | Why It Matters | Effort |
|---|-----|----------------|--------|
| 23 | **Audit trail** | With multiple remote users, you need a record of who called what tool with what parameters. Critical for a security product. | Medium |
| 24 | **Health check endpoints** | `GET /health` for load balancers and monitoring. `GET /ready` for orchestrators (Kubernetes, Cloud Run). | Small |
| 25 | **Circuit breaker** | If ES goes down, every concurrent remote user's request fails and retries pile up. Need to fail fast and probe for recovery. | Medium |
| 26 | **Metrics** | Tool call counts, latency (p50/p95/p99), error rates per tool, active connections. Essential when you can't see the server's console output. | Medium |
| 27 | **Connection pooling** | Multiple concurrent users means many `fetch()` calls to ES. Need HTTP keep-alive / connection reuse (`undici` pool or Node.js agent with `keepAlive: true`). | Small |

### P2 — Nice to Have (additive)

| # | Gap | Why It Matters | Effort |
|---|-----|----------------|--------|
| 28 | **Session management** | Current stateless mode (`sessionIdGenerator: undefined`) can't support streaming notifications or per-session state. | Large |
| 29 | **Multitenancy / user scoping** | Single set of ES credentials for all users. No per-user data isolation. Fine for a POC, not for shared beta. | Large |
| 30 | **Custom connector documentation** | Users need step-by-step instructions for adding the server URL as a Claude.ai custom connector. | Small |
| 31 | **Environment-specific config** | Dev/staging/prod differentiation, feature flags, configurable log levels. | Medium |

### Deployment & Hosting Infrastructure (additive)

The remote version requires standing up a hosted service. `npx cloudflared tunnel` is a POC workaround (ephemeral URLs, no auth, relies on local machine), not a beta solution.

| # | Task | What's Involved | Priority | Effort |
|---|------|-----------------|----------|--------|
| A | **Dockerfile (multi-stage)** | Build stage (compile TS + bundle views) + slim runtime stage. Non-root user, proper signal handling, `.dockerignore`. | P0 | Medium |
| B | **Container registry** | Push built images to GitHub Container Registry, ECR, Artifact Registry, or Docker Hub. Needs CI integration. | P0 | Small |
| C | **Cloud hosting selection & setup** | Pick a platform (Cloud Run, ECS/Fargate, Azure Container Apps, or a VM). Create the service, configure CPU/memory/scaling, set up the network. | P0 | Large |
| D | **Domain & TLS** | Custom domain (e.g., `mcp.yourdomain.com`), DNS config, TLS certificate (Let's Encrypt or cloud-managed). Required for Claude.ai custom connector. | P0 | Medium |
| E | **Secrets management** | ES/Kibana API keys and auth tokens can't be baked into the image. Need cloud-native secrets (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) or injected env vars with restricted access. | P0 | Medium |
| F | **CI/CD pipeline** | GitHub Actions: typecheck, lint, test, build image, push to registry, deploy to hosting. Separate staging and production. | P1 | Large |
| G | **Reverse proxy / load balancer** | Some platforms provide this (Cloud Run, ALB on ECS). On a VM, need nginx or Caddy for TLS termination, request routing, connection management. | P1 | Medium |
| H | **Monitoring & alerting** | Cloud-native monitoring (CloudWatch, Cloud Monitoring) or bring-your-own (Prometheus + Grafana, DataDog). Alerts for: server down, high error rate, high latency, ES connectivity lost. | P1 | Medium |
| I | **Log aggregation** | Structured logs need a searchable sink — CloudWatch Logs, Cloud Logging, ELK, etc. Not just `stdout` on a container that gets recycled. | P1 | Medium |
| J | **Auto-scaling policy** | Min/max instances, scaling triggers (CPU, connections, request count). Without this, a traffic spike either kills the server or costs a fortune. | P2 | Medium |
| K | **Staging environment** | Separate deployment for testing before prod. Same infra, smaller resources. Essential for validating config changes. | P2 | Medium |
| L | **Backup & disaster recovery** | At minimum: documented recovery procedure. Ideally: multi-region or fast re-deploy capability. | P2 | Medium |
| M | **Cost estimation & budget** | Running a container 24/7 + outbound data to ES + cloud secrets + monitoring. Need to size this and set budget alerts. | P2 | Small |

### Estimated Effort for Version 2

```
Version 1 (local-only):          ~2–3 weeks
Version 2 code changes:          ~2–3 weeks (auth, rate limiting, health, metrics, etc.)
Version 2 infra & deployment:    ~2–4 weeks (items A through M above)
                                  ──────────
Total for remote beta:            ~6–10 weeks for one developer
```

The infrastructure work is roughly equal to or greater than the code changes and requires a different skill set (DevOps/platform engineering).

---

## Side-by-Side Summary

```
                                  Local-Only    Remote (additive)
                                  ----------    -----------------
Security
  Auth middleware                      —              P0
  CORS restriction                    —              P0
  Rate limiting                       —              P0
  TLS                                 —              P0

Infrastructure
  Dockerfile                          —              P0
  Cloud hosting                       —              P0
  Domain & DNS                        —              P0
  Secrets management                  —              P0
  CI/CD with deploy                   —              P1
  Reverse proxy / LB                  —              P1
  Monitoring & alerting               —              P1
  Log aggregation                     —              P1
  Auto-scaling                        —              P2
  Staging environment                 —              P2

Code Quality (both versions)
  Bulk NDJSON fix                    P0              P0
  Request timeouts                   P0              P0
  Input validation                   P0              P0
  Silent failures fix                P0              P0
  Tool visibility audit              P0              P0
  Error handling cleanup             P1              P1
  Structured logging                 P1              P1
  Retry logic                        P1              P1
  Graceful shutdown                  P1              P1
  Automated tests                    P2              P2
  Caching                            P2              P2

Remote-Only Code
  McpServer instance reuse            —              P0
  Audit trail                         —              P1
  Health check endpoints              —              P1
  Circuit breaker                     —              P1
  Metrics                             —              P1
  Connection pooling                  —              P1
  Session management                  —              P2
  Multitenancy                        —              P2
```

---

## Key Takeaway

**Local-only beta** is achievable quickly — it's mostly code quality and reliability fixes. The server runs as a child process of Claude Desktop, so the OS handles isolation.

**Remote beta** roughly triples the scope because you're building a deployable, secured, monitored cloud service. The `cloudflared tunnel` workaround lets you demo remote access, but it is not a path to beta (ephemeral URLs, no auth, no uptime guarantee, depends on local machine).

The recommended approach: ship a local-only beta first (Version 1), then layer on the remote deployment infrastructure (Version 2) as a follow-up milestone.

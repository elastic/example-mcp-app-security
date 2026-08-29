# Correlation tools — corpus index prerequisite

The two correlation tools (`diamond_search`, `get_report`) differ from every other tool in this project in one critical way: **they query a custom index that does not exist in a stock Elastic deployment.**

All other tools (alert triage, attack discovery, cases, detection rules, threat hunt) query indices that ship with Elastic Security — `.alerts-security.*`, `.lists-*`, `kibana_cases`, and so on. Those indices are present on any deployment with the Security solution enabled.

The correlation tools query a **custom threat-report corpus** built and maintained by the Kibana [IntelligenceHub](../../CONTRIBUTING.md) plugin (or a compatible ingest pipeline). If that corpus does not exist, `diamond_search` and `get_report` will return empty results or errors.

> [!IMPORTANT]
> **Phase 0 scope:** these tools assume the corpus already exists on the target cluster. Standalone corpus ingest is out of scope here. Point the tools at a cluster that already has the IntelligenceHub plugin and a populated data stream.

---

## The corpus index

### Data stream

| Property | Value |
|----------|-------|
| Pattern matched | `.kibana-threat-reports*` |
| Backing data stream | `.kibana-threat-reports` |
| Mapping mode | `dynamic: strict` — every field must be declared |
| Template version | v14 (see Kibana `setup/index_templates.ts`) |

The data stream uses `dynamic: strict`, so any write that references an undeclared field is rejected. All fields listed below must be present in the index template before any document can be indexed.

---

### Fields the correlation tools depend on

#### Diamond Model extraction — semantic search path

These fields power `diamond_search`'s per-vertex semantic retrieval. They are populated by the IntelligenceHub extraction pipeline (`extract_diamond` step) and require a configured `semantic_text` inference endpoint.

| Field | Type | Notes |
|-------|------|-------|
| `extracted.diamond.adversary.summary` | `semantic_text` | 1–3 sentence behavioural summary of the adversary vertex. Embedded via `DIAMOND_INFERENCE_ENDPOINT_ID` at index time. Empty when `signal` is `NONE`. |
| `extracted.diamond.adversary.signal` | `keyword` | `HIGH` \| `PARTIAL` \| `NONE` — confidence of the extraction. |
| `extracted.diamond.capability.summary` | `semantic_text` | Capability vertex summary. Same inference endpoint. |
| `extracted.diamond.capability.signal` | `keyword` | `HIGH` \| `PARTIAL` \| `NONE` |
| `extracted.diamond.infrastructure.summary` | `semantic_text` | Infrastructure vertex summary. |
| `extracted.diamond.infrastructure.signal` | `keyword` | `HIGH` \| `PARTIAL` \| `NONE` |
| `extracted.diamond.victim.summary` | `semantic_text` | Victim vertex summary. |
| `extracted.diamond.victim.signal` | `keyword` | `HIGH` \| `PARTIAL` \| `NONE` |
| `extracted.diamond.suitable` | `boolean` | `true` when the document has at least one non-NONE vertex and passed the extraction quality gate. **Only `suitable: true` documents are searched.** |
| `extracted.diamond.signal_count` | `integer` | Count of non-NONE vertices (0–4). |
| `extracted.diamond.model_id` | `keyword` | Connector / model that produced the extraction (provenance). |
| `extracted.diamond.extracted_at` | `date` | Wall-clock of the extraction run. |
| `extracted.diamond.extraction_mode` | `keyword` | `single_call` \| `per_vertex_fallback` |

**Inference endpoint requirement:** each `semantic_text` field under `extracted.diamond.*` uses a shared inference endpoint configured at template-creation time (`DIAMOND_INFERENCE_ENDPOINT_ID`). The endpoint must exist and be healthy when documents are indexed; ES validates the `inference_id` at document-index time (not at template PUT). `diamond_search` calls ES `/_msearch` with `{ semantic: { field: "...", query: "..." } }` — this query type requires the inference endpoint to be reachable at search time. When it is unavailable, the service degrades to BM25 (`degraded: true` in the response).

---

#### IOC and actor anchors — exact-match path

These fields power the hash-IOC anchor path in `diamond_search`.

| Field | Type | Notes |
|-------|------|-------|
| `extracted.iocs` | `nested` | Array of `{ type: keyword, value: keyword }` pairs. `type` values: `hash`, `ip`, `domain`, `url`. |
| `extracted.ioc_set_hash` | `keyword` | SHA-256 fingerprint of the full IOC set. Exact match across two reports implies identical infrastructure. |
| `extracted.threat_actors` | `keyword` | Named threat-actor strings (array). |
| `extracted.ttps.techniques` | `keyword` | MITRE ATT&CK technique IDs (array, e.g. `T1059.003`). |

The anchor path requires `extracted.iocs` to be a `nested` type (not a flat object array) so the `nested` query can scope `type` and `value` to the same element. A flat `object` mapping will silently corrupt multi-IOC boolean logic.

---

#### Full-text content — BM25 degradation + `get_report`

| Field | Type | Notes |
|-------|------|-------|
| `content.title` | `semantic_text` | Report headline. `copy_to: ["content.title_bm25"]`. |
| `content.title_bm25` | `text` | BM25-indexed sibling, populated via `copy_to`. Used in the `multi_match` fallback query. |
| `content.body_text` | `semantic_text` | Full report body. `copy_to: ["content.body_text_bm25"]`. |
| `content.body_text_bm25` | `text` | BM25-indexed sibling. Also the target of `match_phrase` in the keyword gap-fill path. |

Both `semantic_text` fields on `content.*` intentionally omit `inference_id` — they inherit the cluster default at index creation (Jina v5, ELSER, or multilingual-e5 depending on the deployment). The BM25 siblings receive their content via `copy_to` at index time; the `copy_to` targets must use full paths (`content.title_bm25`, not `title_bm25`) because `dynamic: strict` rejects root-level field creation.

---

#### Display and linking — returned in stubs and full reports

| Field | Type | Notes |
|-------|------|-------|
| `source.name` | `keyword` | Human-readable feed / vendor name (e.g. `"Mandiant"`, `"CISA"`). Returned as `vendor` in tool responses. |
| `source.type` | `keyword` | Feed type (`rss`, `stix`, `taxii`, `vendor_api`, `telemetry`). Fallback when `source.name` is absent. |
| `source.url` | `keyword` | Canonical URL to the original report. Returned as `url` in tool responses. |
| `severity.level` | `keyword` | Report severity (`critical`, `high`, `medium`, `low`). |
| `provenance.extracted_at` | `date` | Extraction wall-clock. |

---

## Provisioning requirements

To use the correlation tools you need:

1. **The data stream and template** — `PUT _index_template/.kibana-threat-reports-template` with the v14 mapping, then `PUT _data_stream/.kibana-threat-reports`. The IntelligenceHub Kibana plugin does this at startup. There is no standalone provisioning script in this repo.

2. **A `semantic_text` inference endpoint** registered as `DIAMOND_INFERENCE_ENDPOINT_ID` (typically `"threat-report-diamond-embeddings"`, a Jina v5 or ELSER endpoint). Without this, document indexing for diamond fields fails and `diamond_search` always degrades to BM25.

3. **A populated corpus** — documents must have been ingested and enriched by the IntelligenceHub extraction pipeline. Raw ingest without the `extract_diamond` step produces documents with no diamond fields; those documents are excluded from semantic search by the `extracted.diamond.suitable: true` filter.

4. **API key permissions** — the key configured in `CLUSTERS_JSON` must have read access to `.kibana-threat-reports*`. The IntelligenceHub plugin uses a `kibana_system` internal user for writes; the MCP app only reads.

> [!NOTE]
> The `space_id` field on every document provides logical multi-tenancy within a single index. The correlation service in this repo does **not** filter by `space_id` — it searches across all spaces. This matches the MCP server's single-cluster, single-tenant Phase 0 design.

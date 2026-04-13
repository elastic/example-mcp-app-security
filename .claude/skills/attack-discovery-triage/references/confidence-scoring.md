# Confidence Scoring Guide

## Three signals

Attack Discovery confidence is assessed using three bulk signals, not individual alert review:

### 1. Alert Diversity (per finding)

| Alerts | Rules | Severities | Base Confidence |
|--------|-------|------------|-----------------|
| 1 | 1 | Any | Low |
| 2-3 | 1 | Any | Low |
| 3+ | 2+ | Mixed | Moderate |
| 5+ | 2+ | Includes critical/high | High |
| 5+ | 3+ | Multiple MITRE tactics | High |

### 2. Rule Frequency (7-day lookback)

| Alerts/7d | Host spread | Signal |
|-----------|-------------|--------|
| >100 | >5 hosts | Noisy — discount confidence |
| 10-100 | 2-5 hosts | Neutral |
| <10 | 1-2 hosts | High signal — increase confidence |

Rules with >100 alerts across >5 hosts are environmental noise. They may still indicate real threats
when combined with high entity risk, but alone they do not raise confidence.

### 3. Entity Risk

| Risk Level | Score Range | Impact |
|------------|-------------|--------|
| Critical | >90 | Strong increase (+2) |
| High | 70-90 | Increase (+1) |
| Moderate | 40-70 | Neutral |
| Low | 20-40 | Decrease (-0.5) |
| Unknown | <20 | Neutral |

Asset criticality (`extreme_impact`, `high_impact`) further amplifies confidence.

## Synthesis

After collecting all three signals for a finding:

| Composite Score | Confidence Level |
|----------------|-----------------|
| >= 3 | HIGH |
| 1 to 2.9 | MODERATE |
| < 1 | LOW |

The composite score is the sum of:
- Alert diversity: 0 (low), +1 (moderate), +2 (high)
- Severity bonus: +1 for critical, +0.5 for high
- Rule frequency: -1 per noisy rule, +1 per high-signal rule
- Entity risk: per entity values from table above

## What confidence means for triage

| Confidence | Action |
|-----------|--------|
| HIGH | Likely warrants case creation. Present to user for approval. |
| MODERATE | Needs enrichment. Check entity risk detail, process trees, network connections. |
| LOW | Likely noise or insufficient evidence. May be acknowledged without case creation. |

## Base on signals, not narrative

The AD-generated summary may use strong language ("confirmed intrusion", "critical threat") that reflects
the LLM's framing, not evidence. A finding described dramatically but backed by 1 alert from 1 noisy rule
is still LOW confidence. The narrative provides context for investigation — it is not a confidence signal.

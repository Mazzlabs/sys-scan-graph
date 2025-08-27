# sys-scan Intelligence Platform (One-Pager)

## Positioning
A deterministic open-core host scanner (MIT) powering a high-value proprietary Intelligence Layer that converts raw findings into prioritized, explainable, and privacy-aware security narratives. Core delivers trust; Intelligence delivers action.

## Core (Open) vs Intelligence (Proprietary)
| Aspect | Core Scanner (MIT) | Intelligence Layer |
|--------|--------------------|--------------------|
| Purpose | Collect high-signal, deterministic host telemetry | Transform, correlate, prioritize, contextualize |
| Footprint (approx LOC) | ~3K C++ | ~1.24M Python (97% of code) |
| Output | Canonical JSON / NDJSON / SARIF | Enriched JSON, HTML, Diff, Executive Summary |
| Network | Zero outbound | Zero outbound by default (opt-in extensions) |
| Determinism | Canonical ordering & reproducible build toggles | Deterministic enrichment given input + baseline snapshot |
| Extensibility | Add scanners, rules, schemas | Pluggable enrichment stages & adapters |

## Customer Pain Points Solved
| Pain | Symptom Without Us | Our Resolution |
|------|--------------------|----------------|
| Noise & alert fatigue | Thousands of ungrouped signals | Grouped findings + correlation graph compress volume |
| Lack of prioritization | Flat severity-only triage | Multi-factor risk (severity + rarity + correlation) ordering |
| Compliance churn | Fragmented gap data per framework | Normalized gap taxonomy + coverage matrices |
| Slow executive communication | Technical JSON dumps | Auto-generated executive & remediation summaries |
| Rule sprawl & redundancy | Overlapping, stale rule packs | Counterfactual & redundancy analysis suggestions |
| Investigation lag | Manual diffing & context rebuild | Deterministic diff + historical baselines + rationale trails |

## Differentiators
1. Deterministic End-to-End: Identical inputs yield identical enriched outputs (supports audit & attestation).
2. Open-Core Trust Anchor: Minimal, auditable C++ scanner with clean JSON contract – easy to vet, easy to embed.
3. High-Fidelity Correlation Graph: Converts low-impact atomic findings into composite, higher-confidence narratives.
4. Rarity-Driven Prioritization: Baselines reduce noise while elevating anomalous shifts.
5. Compliance Normalization: Unified remediation language across PCI, HIPAA, NIST CSF (extensible).
6. Privacy-First Redaction: Policy-driven hashing/removal pre-export for safer sharing.
7. Extensible & Future-Ready: Rule packs, enrichment stages, adapters evolve without forking the core.

## High-Level Flow
```
Host Scan (Core) -> Canonical JSON -> Intelligence Ingest
                                   -> Validation & Baseline Update
                                   -> Correlation & Rarity Scoring
                                   -> Risk Re-scoring & Coverage Matrices
                                   -> Reports (HTML / Exec / Diff / Enriched JSON)
                                   -> Notifications (Webhook / Slack)
```

## Key Metrics (Illustrative)
| Metric | Impact |
|--------|--------|
| Noise Compression | 40–70% fewer surfaced items after correlation & rarity filters (env dependent) |
| Time-to-Priority | Immediate ordered queue based on composite risk |
| Baseline Convergence | Typical stabilization after 2–3 scans |

(Actual performance varies by environment size and churn characteristics.)

## Deployment Modes
| Mode | Description | Target User |
|------|-------------|-------------|
| Core Only | Fast attestable scan artifact (JSON/SARIF) | Build pipelines, open-source adopters |
| Core + Intelligence (Local) | Full enrichment on analyst workstation or CI runner | Security engineers |
| Fleet Aggregation (Planned) | Multi-host rollups & trend analytics | Security operations / leadership |

## Integration Hooks
- NDJSON streaming for SIEM
- SARIF for code scanning dashboards
- Webhook / Slack notifications for actionable deltas
- Machine-readable enriched JSON for ticket or SOAR ingestion

## Roadmap Highlights
- DAG orchestration for fine-grained enrichment dependency control
- Temporal drift clustering & anomaly explanations
- Package integrity & supply-chain augmentation scanners
- Adaptive suppression guidance (semi-automated rule tuning)
- Signed enriched artifacts with provenance chain

## Licensing Summary
- Core (scanner): MIT – broad reuse and embedding encouraged.
- Intelligence Layer: Proprietary – licensed for evaluation & commercial use; no linkage to core binary.

## Call to Action
Adopt the open-core scanner for immediate visibility; unlock the Intelligence Layer to turn raw host telemetry into fast, defensible security decisions.

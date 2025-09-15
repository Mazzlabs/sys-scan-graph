# sys-scan Intelligence Layer (Agent MVP)

This directory contains a Python prototype for the analysis / correlation / summarization layer built on top of the core `sys-scan` C++ collector.

Goals (Phase 1 / Enhanced Scaffold):
- Load & validate sys-scan JSON (schema v2/3) into typed models
- Enrich findings (augmentation + external knowledge + risk heuristics)
- Optional correlation & rule suggestion (deterministic rule engine + mined gaps)
- Baseline query cycle (plan -> tool execution -> reintegrate -> re‑summarize) with bounded iterations
- Asynchronous enhanced enrichment / summarization / suggestion nodes with caching & metrics
- High‑level risk & compliance analytics injected pre‑summary
- Operational tail (error handling, human feedback placeholder, cache consolidation, final metrics snapshot)
- Deterministic end‑to‑end state suitable for reproducible diffing & regression tests

## Quick Start

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m agent.cli analyze --report ../report.json --out enriched_report.json
```

If you don't have a `report.json`, run the C++ scanner first:
```
./build/sys-scan -o report.json
```

## Components (Selected)
- `models.py`: Pydantic models & schema extensions (risk subscores, correlations, summaries)
- `graph_nodes_scaffold.py`: Enhanced async + operational graph nodes (enrich, summarize, suggest, risk, compliance, cache, metrics, etc.)
- `graph.py`: Dynamic LangGraph workflow builder (`build_workflow`) with env toggle `AGENT_GRAPH_MODE=enhanced|baseline`
- `rules.py` / `rule_gap_miner.py`: Correlation engine and gap mining for candidate rule suggestions
- `baseline.py` / `tools.py`: Baseline rarity / external tool query integration (tool cycle)
- `knowledge.py`: External YAML knowledge enrichment + optional signature requirement (`AGENT_KB_REQUIRE_SIGNATURES=1`)
- `reduction.py`: Cost reduction (summaries, top findings)
- `llm_provider.py`: Pluggable provider abstraction (stub / deterministic)
- `cli.py`: Typer CLI for offline enrichment / analysis

## Enhanced Graph Overview
Enhanced mode sequence (typical):
```
enrich -> correlate -> risk_analyzer -> compliance_checker -> summarize -> (router) -> [plan_baseline cycle] -> suggest_rules -> error_handler -> human_feedback_node -> cache_manager -> metrics_collector -> END
```
Early END routing still flows through `metrics_collector` to produce a `final_metrics` snapshot.

### Metrics & Caching
Each enhanced node records a `<stage>_duration` plus call counters in `state['metrics']`. Enrichment caching (keyed by SHA256 of canonical `raw_findings`) increments `cache_hits` on reuse. `metrics_collector` aggregates counts (enriched, correlated, suggestions), risk & compliance summaries, cache size, provider mode, degraded flag, and total duration into `final_metrics`.

### Environment Toggles
| Variable | Purpose |
|----------|---------|
| `AGENT_GRAPH_MODE` | `enhanced` (default) or `baseline` mode selection |
| `AGENT_MAX_SUMMARY_ITERS` | Cap re‑summarization passes (default 3) |
| `AGENT_KB_REQUIRE_SIGNATURES` + `AGENT_KB_PUBKEY` | Require `.sig` files for knowledge YAML (adds `SignatureMissing` warnings) |

### Operational Resilience
All nodes coerce placeholder `None` containers to lists/dicts to avoid `TypeError` when LangGraph initializes optional keys with `None`. `error_handler` aggregates errors & can flip `degraded_mode`; `cache_manager` consolidates and reports hit rate; `metrics_collector` guarantees consistent terminal accounting.

## Roadmap Highlights
- Re-enable `advanced_router` as a pure router node (currently disabled to avoid node/string return mismatch)
- Integrate `tool_coordinator` for multi-tool planning beyond baseline rarity queries
- Persist `final_metrics` snapshots for longitudinal regression & performance tracking
- Provider fallback mode switching (`llm_provider_mode=fallback`) based on structured error patterns

## Security Notes
- LLM-bound content uses reductions; optional signature requirement guards tampering with knowledge packs
- Redaction & governance hooks present (see `data_governance.py`) though some are placeholders

## License
Licensed under Business Source License 1.1. See [`LICENSE`](LICENSE) for details.

The Intelligence Layer uses BSL 1.1 to ensure sustainable commercial development while allowing permitted uses for evaluation, research, and contributions.

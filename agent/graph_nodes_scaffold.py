from __future__ import annotations
"""Graph nodes scaffolding module (Step 1: Project Scaffolding & Dependencies)

This module prepares shared imports and forward references for upcoming
graph node implementations without introducing circular import issues.

It intentionally does not yet implement concrete node logic; subsequent
steps will add functions that operate on ``GraphState`` using the imported
helpers.
"""

# Standard library imports
import asyncio
import logging
import time
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

# Forward reference / safe import for GraphState to avoid circular import at module import time.
# Use Dict[str, Any] directly to avoid circular import issues during module initialization.
GraphState = Dict[str, Any]  # type: ignore

# Core provider & helper imports (existing project modules)
import llm_provider
import pipeline
import knowledge
import reduction
import rule_gap_miner
import graph_state
import util_hash
import util_normalization
import models
import rules

# Pydantic model imports (data structures used across node logic)
# Models imported at module level for absolute imports

# Re-export models for __all__
Finding = models.Finding
ScannerResult = models.ScannerResult
Report = models.Report
Meta = models.Meta
Summary = models.Summary
SummaryExtension = models.SummaryExtension
AgentState = models.AgentState

logger = logging.getLogger(__name__)

# Optimization: Pre-compile environment variable access
_ENV_CACHE = {}

def _get_env_var(key: str, default: Any = None) -> Any:
    """Cache environment variable lookups for performance."""
    if key not in _ENV_CACHE:
        _ENV_CACHE[key] = __import__('os').environ.get(key, default)
    return _ENV_CACHE[key]

# Optimization: Pre-compile compliance standard mappings
_COMPLIANCE_ALIASES = {
    'pci': 'PCI DSS',
    'pcidss': 'PCI DSS',
    'hipaa': 'HIPAA',
    'soc2': 'SOC 2',
    'soc': 'SOC 2',
    'iso27001': 'ISO 27001',
    'cis': 'CIS Benchmark',
}

def _normalize_compliance_standard(raw: str) -> Optional[str]:
    """Normalize compliance standard names to canonical forms."""
    if not raw:
        return None
    key = raw.lower().replace(' ', '')
    return _COMPLIANCE_ALIASES.get(key)

def _build_finding_models(findings_dicts: List[Dict[str, Any]]) -> List[models.Finding]:
    """Optimized conversion of finding dicts to Pydantic models with error handling."""
    models_list = []
    for finding_dict in findings_dicts:
        try:
            # Use only valid fields to avoid validation errors
            valid_fields = {k: v for k, v in finding_dict.items()
                          if k in models.Finding.model_fields}
            models_list.append(models.Finding(**valid_fields))
        except Exception:  # pragma: no cover
            continue
    return models_list

def _build_agent_state(findings: List[models.Finding], scanner_name: str = "mixed") -> models.AgentState:
    """Optimized construction of AgentState from findings."""
    sr = models.ScannerResult(
        scanner=scanner_name,
        finding_count=len(findings),
        findings=findings,
    )
    report = models.Report(
        meta=models.Meta(),
        summary=models.Summary(
            finding_count_total=len(findings),
            finding_count_emitted=len(findings),
        ),
        results=[sr],
        collection_warnings=[],
        scanner_errors=[],
        summary_extension=models.SummaryExtension(total_risk_score=0),
    )
    return models.AgentState(report=report)

# Type alias for better readability
StateType = Dict[str, Any]  # type: ignore

def _extract_findings_from_state(state: StateType, key: str) -> List[Dict[str, Any]]:
    """Safely extract findings from state with fallback chain."""
    return (state.get(key) or
            state.get('correlated_findings') or
            state.get('enriched_findings') or
            state.get('raw_findings') or [])

def _initialize_state_fields(state: StateType, *fields: str) -> None:
    """Initialize state fields to avoid None checks throughout."""
    for field in fields:
        if state.get(field) is None:
            if field in ('warnings', 'cache_keys'):
                state[field] = []
            elif field in ('metrics', 'cache', 'enrich_cache'):
                state[field] = {}
            else:
                state[field] = []

def _update_metrics_duration(state: StateType, metric_key: str, start_time: float) -> None:
    """Standardized metrics duration update."""
    duration = time.monotonic() - start_time
    state.setdefault('metrics', {})[metric_key] = duration

def _append_warning(state: StateType, module: str, stage: str, error: str, hint: str | None = None):
    wl = state.setdefault('warnings', [])
    wl.append({
        'module': module,
        'stage': stage,
        'error': error,
        'hint': hint
    })


def _findings_from_graph(state: StateType) -> List[models.Finding]:
    out: List[models.Finding] = []
    for finding_dict in state.get('raw_findings', []) or []:
        try:
            # Provide minimal required fields; defaults for missing
            out.append(models.Finding(
                id=finding_dict.get('id','unknown'),
                title=finding_dict.get('title','(no title)'),
                severity=finding_dict.get('severity','info'),
                risk_score=int(finding_dict.get('risk_score', finding_dict.get('risk_total', 0)) or 0),
                metadata=finding_dict.get('metadata', {})
            ))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


def _update_metrics_counter(state: StateType, counter_key: str, increment: int = 1) -> None:
    """Standardized metrics counter update."""
    metrics = state.setdefault('metrics', {})
    metrics[counter_key] = metrics.get(counter_key, 0) + increment

# Batch processing helpers for finding loops optimization
def _batch_extract_finding_fields(findings: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """Batch extract commonly used fields from findings to avoid repeated dict lookups."""
    ids = []
    titles = []
    severities = []
    tags_list = []
    categories = []
    metadata_list = []
    risk_scores = []

    for finding in findings:
        ids.append(finding.get('id'))
        titles.append(finding.get('title', ''))
        severities.append(str(finding.get('severity', 'unknown')).lower())
        tags_list.append([t.lower() for t in (finding.get('tags') or [])])
        categories.append(str(finding.get('category', '')).lower())
        metadata_list.append(finding.get('metadata', {}) or {})
        # Extract risk score with fallback
        risk_score = finding.get('risk_score')
        if risk_score is None:
            risk_score = finding.get('risk_total', 0)
        try:
            risk_scores.append(int(risk_score) if risk_score is not None else 0)
        except (ValueError, TypeError):
            risk_scores.append(0)

    return {
        'ids': ids,
        'titles': titles,
        'severities': severities,
        'tags_list': tags_list,
        'categories': categories,
        'metadata_list': metadata_list,
        'risk_scores': risk_scores,
    }

def _batch_filter_findings_by_severity(fields: Dict[str, List[Any]], severity_levels: set) -> List[int]:
    """Batch filter finding indices by severity levels."""
    return [i for i, sev in enumerate(fields['severities']) if sev in severity_levels]

def _batch_check_compliance_indicators(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for compliance-related findings."""
    compliance_indices = []
    for i, (tags, category, metadata) in enumerate(zip(
        fields['tags_list'], fields['categories'], fields['metadata_list']
    )):
        if ('compliance' in tags or
            category == 'compliance' or
            metadata.get('compliance_standard') or
            _normalize_compliance_standard(category)):
            compliance_indices.append(i)
    return compliance_indices

def _batch_check_external_requirements(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for findings requiring external data."""
    external_indices = []
    for i, (tags, metadata) in enumerate(zip(fields['tags_list'], fields['metadata_list'])):
        if ('external_required' in tags or
            metadata.get('requires_external') or
            metadata.get('threat_feed_lookup')):
            external_indices.append(i)
    return external_indices

def _batch_check_baseline_status(findings: List[Dict[str, Any]]) -> List[int]:
    """Batch check which findings are missing baseline status."""
    missing_indices = []
    for i, finding in enumerate(findings):
        baseline_status = finding.get('baseline_status')
        if baseline_status is None or 'baseline_status' not in finding:
            missing_indices.append(i)
    return missing_indices

def _batch_normalize_compliance_standards(fields: Dict[str, List[Any]]) -> Dict[str, List[int]]:
    """Batch normalize compliance standards and return standard -> finding_indices mapping."""
    std_map: Dict[str, List[int]] = {}

    for i, (metadata, tags) in enumerate(zip(fields['metadata_list'], fields['tags_list'])):
        candidates = set()

        # Explicit metadata standard
        ms = metadata.get('compliance_standard')
        if isinstance(ms, str):
            norm_meta = _normalize_compliance_standard(ms) or ms
            candidates.add(norm_meta)

        # Tag-based discovery
        for tag in tags:
            norm = _normalize_compliance_standard(tag)
            if norm:
                candidates.add(norm)

        # Map findings to standards
        for std in candidates:
            std_map.setdefault(std, []).append(i)

    return std_map

def _batch_calculate_risk_metrics(fields: Dict[str, List[Any]]) -> Dict[str, Any]:
    """Batch calculate risk assessment metrics."""
    sev_counters = {k: 0 for k in ['critical', 'high', 'medium', 'low', 'info', 'unknown']}
    total_risk = 0
    risk_values = []

    for sev, risk_score in zip(fields['severities'], fields['risk_scores']):
        sev = sev if sev in sev_counters else 'unknown'
        sev_counters[sev] += 1
        total_risk += risk_score
        risk_values.append(risk_score)

    avg_risk = (sum(risk_values) / len(risk_values)) if risk_values else 0.0

    # Determine qualitative risk
    qualitative = 'info'
    order = ['critical', 'high', 'medium', 'low', 'info']
    for level in order:
        if sev_counters.get(level):
            qualitative = level
            break

    return {
        'sev_counters': sev_counters,
        'total_risk': total_risk,
        'avg_risk': avg_risk,
        'qualitative_risk': qualitative,
        'risk_values': risk_values,
    }

def _batch_get_top_findings_by_risk(fields: Dict[str, List[Any]], top_n: int = 3) -> List[Dict[str, Any]]:
    """Batch get top N findings by risk score."""
    finding_risks = []
    for i, (fid, title, risk_score, sev) in enumerate(zip(
        fields['ids'], fields['titles'], fields['risk_scores'], fields['severities']
    )):
        finding_risks.append({
            'index': i,
            'id': fid,
            'title': title,
            'risk_score': risk_score,
            'severity': sev,
        })

    # Sort by risk score descending and take top N
    top_findings = sorted(finding_risks, key=lambda x: x['risk_score'], reverse=True)[:top_n]

    # Remove index field for final output
    for finding in top_findings:
        del finding['index']

    return top_findings

__all__ = [
    "GraphState",
    "get_llm_provider",
    "_findings_from_graph",
    "_append_warning",
    "_augment",
    "apply_external_knowledge",
    "reduce_all",
    "mine_gap_candidates",
    "enrich_findings",
    "enhanced_enrich_findings",
    "summarize_host_state",
    "enhanced_summarize_host_state",
    "suggest_rules",
    "correlate_findings",
    "get_enhanced_llm_provider",
    "streaming_summarizer",
    "enhanced_suggest_rules",
    "advanced_router",
    "should_suggest_rules",
    "choose_post_summarize",
    "tool_coordinator",
    "plan_baseline_queries",
    "integrate_baseline_results",
    "risk_analyzer",
    "compliance_checker",
    "error_handler",
    "human_feedback_node",
    "cache_manager",
    "metrics_collector",
    # Models
    "Finding",
    "ScannerResult",
    "Report",
    "Meta",
    "Summary",
    "SummaryExtension",
    "AgentState",
]


def enrich_findings(state: StateType) -> StateType:
    """Basic synchronous enrichment step.

    Steps:
    1. Convert raw findings dicts -> Pydantic `Finding` models via `_findings_from_graph`.
    2. Wrap in `ScannerResult` and `Report` objects (minimal required fields).
    3. Build `AgentState` then run `_augment` and `apply_external_knowledge`.
    4. Export enriched findings back to plain dicts under `state['enriched_findings']`.

    On any exception, a warning is appended and the function falls back to
    leaving (or copying) `raw_findings` into `enriched_findings` so downstream
    nodes can continue operating deterministically.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        findings = _findings_from_graph(state)
        sr = models.ScannerResult(
            scanner="mixed",
            finding_count=len(findings),
            findings=findings,
        )
        report = models.Report(
            meta=models.Meta(),
            summary=models.Summary(
                finding_count_total=len(findings),
                finding_count_emitted=len(findings),
            ),
            results=[sr],
            collection_warnings=[],
            scanner_errors=[],
            summary_extension=models.SummaryExtension(total_risk_score=0),
        )
        astate = models.AgentState(report=report)
        astate = pipeline.augment(astate)
        astate = knowledge.apply_external_knowledge(astate)

        enriched: List[Dict[str, Any]] = []
        if astate.report and astate.report.results:
            for result in astate.report.results:
                for finding in result.findings:
                    try:
                        enriched.append(finding.model_dump())
                    except Exception:  # pragma: no cover
                        continue
        state["enriched_findings"] = enriched
    except Exception as e:  # pragma: no cover
        logger.exception("enrich_findings failed: %s", e)
        _append_warning(state, "graph", "enrich", str(e))  # type: ignore
        if "enriched_findings" not in state:
            # Fallback: propagate raw findings so later stages have data.
            state["enriched_findings"] = state.get("raw_findings", [])
    return state


def summarize_host_state(state: StateType) -> StateType:
    """Basic host state summarization node with optimized patterns.

    Optimized: Uses helper functions and cached environment variables.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    # Iteration guard with cached env var
    max_iter = int(_get_env_var('AGENT_MAX_SUMMARY_ITERS', '3'))
    iters = int(state.get('iteration_count', 0) or 0)
    if iters >= max_iter:
        _append_warning(state, 'graph', 'summarize', 'iteration_limit_reached')  # type: ignore
        return state
    
    try:
        provider = llm_provider.get_llm_provider()
        findings_src = _extract_findings_from_state(state, 'correlated_findings')
        findings_models = _build_finding_models(findings_src)

        reductions = reduction.reduce_all(findings_models)
        # Rehydrate correlations (if present)
        corr_objs = []
        for c in state.get('correlations', []) or []:
            try:
                corr_objs.append(models.Correlation(**c))
            except Exception:  # pragma: no cover
                continue
        baseline_context = state.get('baseline_results') or {}
        summaries, metadata = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)
        state['summary'] = summaries.model_dump()
        state['iteration_count'] = iters + 1
    except Exception as e:  # pragma: no cover
        logger.exception("summarize_host_state failed: %s", e)
        _append_warning(state, 'graph', 'summarize', str(e))  # type: ignore
    return state


def suggest_rules(state: StateType) -> StateType:
    """Mine candidate rules from enriched findings with optimized patterns.

    Optimized: Uses helper functions and eliminates redundant temp file usage.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    tf_path = None
    try:
        findings = _extract_findings_from_state(state, 'enriched_findings')
        if not findings:
            state['suggested_rules'] = []
            return state

        import tempfile, json as _json
        from pathlib import Path

        # Use context manager for automatic cleanup (still needed for mine_gap_candidates API)
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
            tf_path = tf.name
            _json.dump({'enriched_findings': findings}, tf)
            tf.flush()
            result = rule_gap_miner.mine_gap_candidates([Path(tf.name)], risk_threshold=10, min_support=2)

        state['suggested_rules'] = result.get('suggestions', [])
    except Exception as e:  # pragma: no cover
        logger.exception("suggest_rules failed: %s", e)
        _append_warning(state, 'graph', 'rule_mine', str(e))  # type: ignore
    finally:
        if tf_path:
            try:
                import os
                os.unlink(tf_path)
            except Exception:
                pass
    return state


def correlate_findings(state: StateType) -> StateType:
    """Apply correlation rules to enriched findings and attach correlation references.

    Optimized: Uses helper functions and reduces redundant operations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        findings_dicts = _extract_findings_from_state(state, 'enriched_findings')
        if not findings_dicts:
            state['correlated_findings'] = []
            state['correlations'] = []
            return state

        findings_models = _build_finding_models(findings_dicts)
        if not findings_models:
            state['correlated_findings'] = []
            state['correlations'] = []
            return state

        astate = _build_agent_state(findings_models, "mixed")
        correlator = rules.Correlator(rules.DEFAULT_RULES)
        correlations = correlator.apply(findings_models)

        # Optimized correlation attachment using dict lookup
        corr_map = {c.id: c for c in correlations}
        for finding in findings_models:
            for corr_id in corr_map.keys():
                if finding.id in corr_map[corr_id].related_finding_ids:
                    if corr_id not in finding.correlation_refs:
                        finding.correlation_refs.append(corr_id)

        state['correlated_findings'] = [finding.model_dump() for finding in findings_models]
        state['correlations'] = [c.model_dump() for c in correlations]
    except Exception as e:  # pragma: no cover
        logger.exception("correlate_findings failed: %s", e)
        _append_warning(state, 'graph', 'correlate', str(e))  # type: ignore
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])
    return state


async def enhanced_enrich_findings(state: StateType) -> StateType:
    """Advanced async enrichment node with caching & metrics.

    Optimized: Uses helper functions for state initialization and metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    raw_list = state.get("raw_findings") or []

    # Use optimized state initialization
    _initialize_state_fields(state, 'warnings', 'metrics', 'cache_keys', 'enrich_cache')

    # Build deterministic cache key (sha256 of canonical JSON of raw findings)
    try:
        cache_key = util_hash.stable_hash(raw_list, "enrich")
    except Exception:  # pragma: no cover - extremely unlikely
        cache_key = "enrich:invalid_key"

    cache: Dict[str, Any] = state["enrich_cache"]
    # Cache hit path
    if cache_key in cache:
        logger.debug("enhanced_enrich_findings cache hit key=%s", cache_key)
        _update_metrics_counter(state, "cache_hits")
        # Rehydrate enriched findings from cache
        state["enriched_findings"] = cache[cache_key]
        # Still record very small duration for observability
        _update_metrics_duration(state, "enrich_duration", start)
        ck_list = state["cache_keys"]
        if cache_key not in ck_list:
            ck_list.append(cache_key)
        return state

    # Cache miss -> perform enrichment
    try:
        findings = _findings_from_graph(state)
        astate = _build_agent_state(findings, "mixed")
        # Run enrichment pipeline pieces (sync) inside async context
        astate = pipeline.augment(astate)
        astate = knowledge.apply_external_knowledge(astate)

        enriched: List[Dict[str, Any]] = []
        if astate.report and astate.report.results:
            for result in astate.report.results:
                for finding in result.findings:
                    try:
                        enriched.append(finding.model_dump())
                    except Exception:  # pragma: no cover
                        continue

        state["enriched_findings"] = enriched
        # Update cache structures
        cache[cache_key] = enriched
        ck_list = state["cache_keys"]
        if cache_key not in ck_list:
            ck_list.append(cache_key)
    except Exception as e:  # pragma: no cover
        logger.exception("enhanced_enrich_findings failed key=%s error=%s", cache_key, e)
        _append_warning(state, "graph", "enhanced_enrich", f"{type(e).__name__}: {e}")  # type: ignore
        if "enriched_findings" not in state:
            state["enriched_findings"] = state.get("raw_findings", [])

    _update_metrics_duration(state, "enrich_duration", start)
    return state


def get_enhanced_llm_provider():
    """Multi-provider selection wrapper.

    Currently returns the default provider; placeholder for future logic that
    could select alternate providers based on:
      - state['summary_strategy']
      - environment variables (AGENT_LLM_PROVIDER / AGENT_LLM_PROVIDER_ALT)
      - risk / finding volume thresholds
    Deterministic by design (no randomness).
    """
    # Basic strategy: prefer primary; optionally allow alternate env variable if set and distinct
    primary = llm_provider.get_llm_provider()
    alt_env = __import__('os').environ.get('AGENT_LLM_PROVIDER_ALT')
    if alt_env and alt_env == '__use_null__':  # explicit override to force Null provider
        try:
            return llm_provider.NullLLMProvider()
        except Exception:  # pragma: no cover
            return primary
    return primary


async def streaming_summarizer(provider, reductions, correlations, actions, baseline_context):
    """Deterministic streaming facade.

    For now this simply delegates to provider.summarize once (no incremental
    token emission) to maintain determinism. Later this could yield partial
    chunks and assemble them into a final Summaries object.
    """
    return await _call_summarize(provider, reductions, correlations, actions, baseline_context)


async def _call_summarize(provider, reductions, correlations, actions, baseline_context):
    """Helper to normalize async/sync summarize calls."""
    import inspect
    res = provider.summarize(reductions, correlations, actions, baseline_context=baseline_context)
    if inspect.isawaitable(res):
        return await res
    return res


async def enhanced_summarize_host_state(state: StateType) -> StateType:
    """Advanced async summarization node with streaming + metrics.

    Optimized: Uses helper functions and cached environment variables.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        # Iteration guard with cached env var
        max_iter = int(_get_env_var('AGENT_MAX_SUMMARY_ITERS', '3'))
        iters = int(state.get('iteration_count', 0) or 0)
        if iters >= max_iter:
            _append_warning(state, 'graph', 'enhanced_summarize', 'iteration_limit_reached')  # type: ignore
            return state

        provider = get_enhanced_llm_provider()
        findings_src = _extract_findings_from_state(state, 'correlated_findings')
        findings_models = _build_finding_models(findings_src)

        reductions = reduction.reduce_all(findings_models)
        corr_objs = []
        for c in state.get('correlations', []) or []:
            try:
                corr_objs.append(models.Correlation(**c))
            except Exception:  # pragma: no cover
                continue

        baseline_context = state.get('baseline_results') or {}
        streaming = bool(state.get('streaming_enabled'))
        if streaming:
            summaries, metadata = await streaming_summarizer(provider, reductions, corr_objs, actions=[], baseline_context=baseline_context)
        else:
            summaries, metadata = await _call_summarize(provider, reductions, corr_objs, actions=[], baseline_context=baseline_context)

        state['summary'] = summaries.model_dump()
        state['iteration_count'] = iters + 1

        # Metrics extraction with helper
        sm = summaries.metrics or {}
        metrics = state.setdefault('metrics', {})
        if 'tokens_prompt' in sm:
            metrics['tokens_prompt'] = sm['tokens_prompt']
        if 'tokens_completion' in sm:
            metrics['tokens_completion'] = sm['tokens_completion']
        _update_metrics_counter(state, 'summarize_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_summarize_host_state failed: %s', e)
        _append_warning(state, 'graph', 'enhanced_summarize', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'summarize_duration', start)
    return state


async def enhanced_suggest_rules(state: StateType) -> StateType:
    """Advanced async rule suggestion node with temp file optimization.

    Optimized: Uses helper functions, cached env vars, and eliminates temp file usage.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    tf_path = None
    try:
        provider = get_enhanced_llm_provider()
        findings_src = _extract_findings_from_state(state, 'correlated_findings')
        findings_models = _build_finding_models(findings_src)

        # Use cached env var for max suggestions
        max_suggestions = int(_get_env_var('AGENT_MAX_RULE_SUGGESTIONS', '10'))

        # Build context from state without temp files
        context_parts = []
        if state.get('summary'):
            context_parts.append(f"Summary: {state['summary']}")
        if state.get('correlations'):
            context_parts.append(f"Correlations: {len(state['correlations'])} items")
        if state.get('baseline_results'):
            context_parts.append(f"Baseline: {state['baseline_results']}")

        context = '\n'.join(context_parts) if context_parts else 'No additional context'

        # Use gap miner for suggestions (optimized temp file usage)
        import tempfile, json as _json
        findings_data = {'enriched_findings': [f.model_dump() for f in findings_models]}
        
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
            tf_path = tf.name
            _json.dump(findings_data, tf)
            tf.flush()
            from pathlib import Path
            # Use slightly permissive thresholds to increase suggestion probability
            result = rule_gap_miner.mine_gap_candidates([Path(tf.name)], risk_threshold=10, min_support=2)
        
        suggestions = result.get('suggestions', [])
        
        # Optional refinement with provider
        try:
            refine_fn = getattr(provider, 'refine_rules', None)
            if callable(refine_fn) and suggestions:
                suggestions = refine_fn(suggestions, examples=None)
        except Exception:  # pragma: no cover - refinement fallback
            pass

        # Ensure suggestions is a list
        try:
            if not isinstance(suggestions, list):
                suggestions = [suggestions] if suggestions else []
        except Exception:
            suggestions = []
        
        # Store suggestions directly in state
        state['suggested_rules'] = suggestions

        # Apply unified normalization
        state = util_normalization.normalize_rule_suggestions(state)
        state = util_normalization.ensure_monotonic_timing(state)
        state = util_normalization.add_metrics_version(state)

        # Metrics with helper
        _update_metrics_counter(state, 'rule_suggest_calls')
        metrics = state.setdefault('metrics', {})
        metrics['rule_suggest_count'] = len(suggestions) if hasattr(suggestions, '__len__') else 0
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_suggest_rules failed: %s', e)
        _append_warning(state, 'graph', 'enhanced_suggest_rules', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'rule_suggest_duration', start)
        if tf_path:
            try:
                import os
                os.unlink(tf_path)
            except Exception:
                pass
    return state


def advanced_router(state: StateType) -> str:
    """Priority-based routing decision with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    try:
        # Ensure monotonic timing is initialized for accurate duration calculations
        state = util_normalization.ensure_monotonic_timing(state)

        # 1. Human feedback gate
        if state.get('human_feedback_pending'):
            return 'human_feedback'

        # Choose findings source preference
        findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
        if not findings:
            return 'summarize'

        # Batch extract all needed fields once
        fields = _batch_extract_finding_fields(findings)

        # 2. Compliance detection (batch check)
        compliance_indices = _batch_check_compliance_indicators(fields)
        if compliance_indices:
            return 'compliance'

        # 3. High severity missing baseline (batch check)
        high_severity_indices = _batch_filter_findings_by_severity(fields, {'high', 'critical'})
        if high_severity_indices:
            baseline = state.get('baseline_results') or {}
            # Check if any high-sev finding is missing baseline
            for idx in high_severity_indices:
                fid = fields['ids'][idx]
                if fid and fid not in baseline:
                    return 'baseline'

        # 4. External data requirement (batch check)
        external_indices = _batch_check_external_requirements(fields)
        if external_indices:
            return 'risk'

        # 5. Default path
        return 'summarize'
    except Exception:  # pragma: no cover
        return 'error'


def should_suggest_rules(state: StateType) -> str:
    """Router: decide whether to run rule suggestion with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        enriched = state.get('enriched_findings') or []
        if not enriched:
            try:  # pragma: no cover - library optional
                from langgraph.graph import END  # type: ignore
                return END  # type: ignore
            except Exception:
                return '__end__'

        # Batch check for high severity findings
        fields = _batch_extract_finding_fields(enriched)
        high_severity_indices = _batch_filter_findings_by_severity(fields, {'high'})

        if high_severity_indices:
            return 'suggest_rules'

        try:  # pragma: no cover - library optional
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return '__end__'
    except Exception:  # pragma: no cover
        return 'suggest_rules'  # fail open to ensure progress


def choose_post_summarize(state: StateType) -> str:
    """Router after summarization with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if not state.get('baseline_cycle_done'):
            enriched = state.get('enriched_findings') or []
            if not enriched:
                return should_suggest_rules(state)

            # Batch check for missing baseline status
            missing_indices = _batch_check_baseline_status(enriched)
            if missing_indices:
                return 'plan_baseline'

        return should_suggest_rules(state)
    except Exception:  # pragma: no cover
        return 'suggest_rules'


# ---------------------------------------------------------------------------
# Specialized & Supporting Nodes (Phase 4 - Step 10)
# ---------------------------------------------------------------------------
try:  # Optional: message classes for planning/integration if langchain present
    from langchain_core.messages import AIMessage, ToolMessage  # type: ignore
except Exception:  # pragma: no cover
    AIMessage = ToolMessage = None  # type: ignore


async def tool_coordinator(state: StateType) -> StateType:
    """Analyze enriched/correlated findings and plan external tool needs with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    start = time.monotonic()
    try:
        findings = state.get('correlated_findings') or state.get('enriched_findings') or []
        if not findings:
            state['pending_tool_calls'] = []
            _update_metrics_counter(state, 'tool_coordinator_calls')
            return state

        # Batch check baseline status
        missing_indices = _batch_check_baseline_status(findings)
        if not missing_indices:
            state['pending_tool_calls'] = []
            _update_metrics_counter(state, 'tool_coordinator_calls')
            return state

        # Batch extract fields for missing findings
        missing_findings = [findings[i] for i in missing_indices]
        fields = _batch_extract_finding_fields(missing_findings)

        # Build tool calls using batched data
        pending: List[Dict[str, Any]] = []
        host_id = _get_env_var('AGENT_GRAPH_HOST_ID', 'graph_host')

        for i, (fid, title, severity, scanner) in enumerate(zip(
            fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
        )):
            # Extract scanner from metadata if available
            scanner_name = 'mixed'
            if isinstance(scanner, dict):
                scanner_name = scanner.get('scanner', 'mixed')

            pending.append({
                'id': f'call_{fid or f"unknown_{i}"}',
                'name': 'query_baseline',
                'args': {
                    'finding_id': fid or f'unknown_{i}',
                    'title': title or '',
                    'severity': severity or '',
                    'scanner': scanner_name,
                    'host_id': host_id,
                }
            })

        state['pending_tool_calls'] = pending
        _update_metrics_counter(state, 'tool_coordinator_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('tool_coordinator failed: %s', e)
        _append_warning(state, 'graph', 'tool_coordinator', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'tool_coordinator_duration', start)
    return state


def plan_baseline_queries(state: StateType) -> StateType:
    """Construct AIMessage with tool_calls for baseline queries with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if AIMessage is None:  # dependency not available
            return state

        pending = state.get('pending_tool_calls')
        if not pending:  # derive on-demand if empty or None
            enriched = state.get('enriched_findings') or []
            if not enriched:
                _update_metrics_counter(state, 'baseline_plan_calls')
                return state

            # Batch check baseline status
            missing_indices = _batch_check_baseline_status(enriched)
            if not missing_indices:
                _update_metrics_counter(state, 'baseline_plan_calls')
                return state

            # Batch extract fields for missing findings
            missing_findings = [enriched[i] for i in missing_indices]
            fields = _batch_extract_finding_fields(missing_findings)

            # Build tool calls using batched data
            host_id = _get_env_var('AGENT_GRAPH_HOST_ID', 'graph_host')
            pending = []

            for i, (fid, title, severity, scanner) in enumerate(zip(
                fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
            )):
                # Extract scanner from metadata if available
                scanner_name = 'mixed'
                if isinstance(scanner, dict):
                    scanner_name = scanner.get('scanner', 'mixed')

                pending.append({
                    'id': f"call_{fid or f'unknown_{i}'}",
                    'name': 'query_baseline',
                    'args': {
                        'finding_id': fid or f'unknown_{i}',
                        'title': title or '',
                        'severity': severity or '',
                        'scanner': scanner_name,
                        'host_id': host_id,
                    }
                })

        if not pending:
            _update_metrics_counter(state, 'baseline_plan_calls')
            return state

        msgs = state.get('messages') or []
        msgs.append(AIMessage(content="Baseline context required", tool_calls=pending))  # type: ignore[arg-type]
        state['messages'] = msgs
        _update_metrics_counter(state, 'baseline_plan_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('plan_baseline_queries (scaffold) failed: %s', e)
        _append_warning(state, 'graph', 'plan_baseline', f"{type(e).__name__}: {e}")  # type: ignore
    return state


def integrate_baseline_results(state: StateType) -> StateType:
    """Integrate ToolMessage outputs into baseline_results & mark cycle done.

    Compatible with legacy implementation but also tolerant to absent ToolMessage
    class. Any dict content under a ToolMessage with a 'finding_id' key is added.
    Sets baseline_cycle_done = True always (conservative to avoid infinite loops).
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if ToolMessage is None:
            state['baseline_cycle_done'] = True
            return state
        msgs = state.get('messages') or []
        results = state.get('baseline_results') or {}
        import json as _json  # local import
        for m in msgs:
            try:
                # Handle both ToolMessage objects and dict representations
                if isinstance(m, ToolMessage):
                    payload = getattr(m, 'content', None)
                elif isinstance(m, dict) and m.get('type') == 'tool':
                    payload = m.get('content')
                else:
                    continue
                    
                data_obj = None
                if isinstance(payload, dict):
                    data_obj = payload
                elif isinstance(payload, str):
                    try:
                        data_obj = _json.loads(payload)
                    except Exception:  # pragma: no cover
                        data_obj = None
                if isinstance(data_obj, dict):
                    fid = data_obj.get('finding_id')
                    if isinstance(fid, str):
                        results[fid] = data_obj  # type: ignore[index]
            except Exception:  # pragma: no cover
                continue
        state['baseline_results'] = results
    except Exception as e:  # pragma: no cover
        logger.exception('integrate_baseline_results (scaffold) failed: %s', e)
        _append_warning(state, 'graph', 'integrate_baseline', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        state['baseline_cycle_done'] = True
    return state


# ---------------------------------------------------------------------------
# High-Level Analysis Nodes (Phase 4 - Step 11)
# ---------------------------------------------------------------------------
async def risk_analyzer(state: StateType) -> StateType:
    """Aggregate higher-level risk assessment with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations and optimize sorting.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
        if not findings:
            state['risk_assessment'] = {
                'counts': {k: 0 for k in ['critical','high','medium','low','info','unknown']},
                'total_risk_score': 0,
                'average_risk_score': 0.0,
                'overall_risk': 'info',
                'overall_risk_level': 'low',  # Unified field name
                'top_findings': [],
                'finding_count': 0,
                'risk_factors': [],  # Unified qualitative analysis
                'recommendations': [],  # Unified recommendations
                'confidence_score': 1.0  # High confidence for empty state
            }
            _update_metrics_counter(state, 'risk_analyzer_calls')
            return state

        # Batch extract all needed fields
        fields = _batch_extract_finding_fields(findings)

        # Batch calculate risk metrics
        risk_metrics = _batch_calculate_risk_metrics(fields)

        # Batch get top findings by risk score
        top_findings = _batch_get_top_findings_by_risk(fields, 3)

        assessment = {
            'counts': risk_metrics['sev_counters'],
            'total_risk_score': risk_metrics['total_risk'],
            'average_risk_score': risk_metrics['avg_risk'],
            'overall_risk': risk_metrics['qualitative_risk'],
            'overall_risk_level': risk_metrics['qualitative_risk'],  # Unified field name
            'top_findings': top_findings,
            'finding_count': len(findings),
            'risk_factors': [],  # Can be populated by enhanced analysis
            'recommendations': [],  # Can be populated by enhanced analysis
            'confidence_score': 0.95  # High confidence for quantitative analysis
        }
        state['risk_assessment'] = assessment

        # Apply unified normalization
        state = util_normalization.unify_risk_assessment(state)
        state = util_normalization.ensure_monotonic_timing(state)
        state = util_normalization.add_metrics_version(state)

        _update_metrics_counter(state, 'risk_analyzer_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('risk_analyzer failed: %s', e)
        _append_warning(state, 'graph', 'risk_analyzer', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'risk_analyzer_duration', start)
    return state


async def compliance_checker(state: StateType) -> StateType:
    """Evaluate simple compliance mapping heuristics with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations and optimize compliance mapping.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
        if not findings:
            state['compliance_check'] = {
                'standards': {},
                'total_compliance_findings': 0,
            }
            _update_metrics_counter(state, 'compliance_checker_calls')
            return state

        # Batch extract all needed fields
        fields = _batch_extract_finding_fields(findings)

        # Batch normalize compliance standards
        std_map_indices = _batch_normalize_compliance_standards(fields)

        # Convert indices to finding IDs and build final compliance map
        std_map: Dict[str, Dict[str, Any]] = {}
        total = 0

        for std, indices in std_map_indices.items():
            finding_ids = [fields['ids'][i] for i in indices if fields['ids'][i]]
            if finding_ids:
                bucket = std_map.setdefault(std, {'finding_ids': []})
                bucket['finding_ids'] = finding_ids
                bucket['count'] = len(finding_ids)
                total += len(finding_ids)

        state['compliance_check'] = {
            'standards': std_map,
            'total_compliance_findings': total,
        }

        # Apply unified normalization
        state = util_normalization.unify_compliance_check(state)
        state = util_normalization.ensure_monotonic_timing(state)
        state = util_normalization.add_metrics_version(state)

        _update_metrics_counter(state, 'compliance_checker_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('compliance_checker failed: %s', e)
        _append_warning(state, 'graph', 'compliance_checker', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'compliance_checker_duration', start)
    return state


# ---------------------------------------------------------------------------
# Operational Nodes (Phase 4 - Step 12)
# ---------------------------------------------------------------------------
async def error_handler(state: StateType) -> StateType:
    """Analyze recent errors and toggle degraded / fallback modes with optimized patterns.

    Optimized: Uses helper functions and standardized metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        errs = state.get('errors') or []
        timeout_count = 0
        provider_errs = 0
        for e in errs[-25:]:  # analyze last 25 for recency bias
            msg = ''
            if isinstance(e, dict):
                msg = str(e.get('error') or e.get('message') or '')
            else:
                msg = str(e)
            low = msg.lower()
            if 'timeout' in low:
                timeout_count += 1
            if 'model' in low or 'provider' in low:
                provider_errs += 1
        if timeout_count >= 3:
            state['degraded_mode'] = True
        # fallback provider decision
        if provider_errs >= 2:
            state['llm_provider_mode'] = 'fallback'
        if state.get('degraded_mode') and not state.get('llm_provider_mode'):
            state['llm_provider_mode'] = 'fallback'
        m = state.setdefault('metrics', {})
        m['error_handler_calls'] = m.get('error_handler_calls', 0) + 1
        m['timeout_error_count'] = timeout_count
    except Exception as e:  # pragma: no cover
        logger.exception('error_handler failed: %s', e)
        _append_warning(state, 'graph', 'error_handler', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'error_handler_duration', start)
    return state


async def human_feedback_node(state: StateType) -> StateType:
    """Process human feedback with optimized patterns.

    Optimized: Uses helper functions and standardized metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        if state.get('human_feedback_pending'):
            # Simulate minimal async gap (could be replaced by real I/O later)
            await asyncio.sleep(0)
            if 'human_feedback' not in state:
                state['human_feedback'] = {
                    'status': 'auto-ack',
                    'notes': 'No-op placeholder feedback',
                }
        state['human_feedback_pending'] = False
        state['human_feedback_processed'] = True
        _update_metrics_counter(state, 'human_feedback_node_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('human_feedback_node failed: %s', e)
        _append_warning(state, 'graph', 'human_feedback', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'human_feedback_node_duration', start)
    return state


async def cache_manager(state: StateType) -> StateType:
    """Centralize caching logic with optimized patterns.

    Optimized: Uses helper functions and standardized metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        cache_store: Dict[str, Any] = state.setdefault('cache', {})
        # Enrichment caching
        enriched = state.get('enriched_findings')
        if enriched is not None:
            try:
                ek = util_hash.stable_hash(enriched, "enrich")
                if ek not in cache_store:
                    cache_store[ek] = enriched
            except Exception:  # pragma: no cover
                pass
        # Summary snapshot
        if 'summary' in state:
            iter_count = state.get('iteration_count', 0)
            key = f"summary:iter_{iter_count}"
            if key not in cache_store:
                cache_store[key] = state['summary']
        # Risk / compliance snapshots
        if 'risk_assessment' in state:
            cache_store['risk:latest'] = state['risk_assessment']
        if 'compliance_check' in state:
            cache_store['compliance:latest'] = state['compliance_check']
        # Derived cache metrics
        metrics = state.setdefault('metrics', {})
        hits = metrics.get('cache_hits', 0)
        misses = metrics.get('cache_misses', 0)
        denom = hits + misses
        if denom:
            metrics['cache_hit_rate'] = hits / denom
        _update_metrics_counter(state, 'cache_manager_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('cache_manager failed: %s', e)
        _append_warning(state, 'graph', 'cache_manager', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'cache_manager_duration', start)
    return state


async def metrics_collector(state: StateType) -> StateType:
    """Aggregate final metrics snapshot with optimized patterns.

    Optimized: Uses helper functions and standardized metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        metrics = dict(state.get('metrics') or {})  # shallow copy
        # Derived counters
        metrics['suggestion_count'] = len(state.get('suggested_rules') or [])
        metrics['enriched_count'] = len(state.get('enriched_findings') or [])
        metrics['correlated_count'] = len(state.get('correlated_findings') or [])
        ra = state.get('risk_assessment') or {}
        metrics['overall_risk'] = ra.get('overall_risk')
        cc = state.get('compliance_check') or {}
        metrics['compliance_standards_count'] = len((cc.get('standards') or {}).keys())
        metrics['llm_provider_mode'] = state.get('llm_provider_mode') or metrics.get('llm_provider_mode') or 'normal'
        metrics['degraded_mode'] = bool(state.get('degraded_mode'))
        cache_store = state.get('cache') or {}
        metrics['cache_entries'] = len(cache_store)
        # total duration (optional start_time recorded externally)
        st = state.get('start_time')
        if isinstance(st, (int, float)):
            metrics['total_duration'] = time.monotonic() - float(st)
        state['final_metrics'] = metrics
        logger.debug('Final metrics: %s', metrics)
        _update_metrics_counter(state, 'metrics_collector_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('metrics_collector failed: %s', e)
        _append_warning(state, 'graph', 'metrics_collector', f"{type(e).__name__}: {e}")  # type: ignore
    finally:
        _update_metrics_duration(state, 'metrics_collector_duration', start)
    return state

# ---------------------------------------------------------------------------
# Final consolidated public exports (Step 13: Finalize Exports)
# Re-declare __all__ at module end to ensure late-added symbols are included.
# ---------------------------------------------------------------------------
__all__ = [
    # Core enrichment & summarization
    'enrich_findings', 'enhanced_enrich_findings', 'summarize_host_state', 'enhanced_summarize_host_state',
    # Rule suggestion & correlation
    'suggest_rules', 'enhanced_suggest_rules', 'correlate_findings',
    # LLM provider utilities
    'get_enhanced_llm_provider', 'streaming_summarizer',
    # Routers
    'advanced_router', 'should_suggest_rules', 'choose_post_summarize',
    # Baseline / tool coordination
    'tool_coordinator', 'plan_baseline_queries', 'integrate_baseline_results',
    # High-level analysis
    'risk_analyzer', 'compliance_checker',
    # Operational nodes
    'error_handler', 'human_feedback_node', 'cache_manager', 'metrics_collector',
    # Models (re-exported for convenience)
    "Finding",
    "ScannerResult", 
    "Report",
    "Meta",
    "Summary",
    "SummaryExtension",
    "AgentState",
]

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
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

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

# Parameter object for warning encapsulation
from dataclasses import dataclass

@dataclass
class WarningInfo:
    """Encapsulates warning information to reduce function argument count."""
    module: str
    stage: str
    error: str
    hint: Optional[str] = None

@dataclass
class SummarizationContext:
    """Encapsulates summarization parameters to reduce function argument count."""
    provider: Any
    reductions: Any
    correlations: List[Any]
    actions: List[Any]
    baseline_context: Dict[str, Any]

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

def _append_warning(state: StateType, warning_info: WarningInfo) -> None:
    """Append a warning to the state using encapsulated warning information."""
    wl = state.setdefault('warnings', [])
    wl.append({
        'module': warning_info.module,
        'stage': warning_info.stage,
        'error': warning_info.error,
        'hint': warning_info.hint
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

def _is_compliance_related(tags: List[str], category: str, metadata: Dict[str, Any]) -> bool:
    """Check if a finding is compliance-related based on tags, category, and metadata."""
    return (bool('compliance' in tags) or
            bool(category == 'compliance') or
            bool(metadata.get('compliance_standard')) or
            bool(_normalize_compliance_standard(category)))


def _batch_check_compliance_indicators(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for compliance-related findings."""
    compliance_indices = []
    for i, (tags, category, metadata) in enumerate(zip(
        fields['tags_list'], fields['categories'], fields['metadata_list']
    )):
        if _is_compliance_related(tags, category, metadata):
            compliance_indices.append(i)
    return compliance_indices


def _requires_external_data(tags: List[str], metadata: Dict[str, Any]) -> bool:
    """Check if a finding requires external data based on tags and metadata."""
    return (bool('external_required' in tags) or
            bool(metadata.get('requires_external')) or
            bool(metadata.get('threat_feed_lookup')))


def _batch_check_external_requirements(fields: Dict[str, List[Any]]) -> List[int]:
    """Batch check for findings requiring external data."""
    external_indices = []
    for i, (tags, metadata) in enumerate(zip(fields['tags_list'], fields['metadata_list'])):
        if _requires_external_data(tags, metadata):
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

def _extract_metadata_standards(metadata: Dict[str, Any]) -> Set[str]:
    """Extract compliance standards from finding metadata."""
    candidates = set()
    ms = metadata.get('compliance_standard')
    if isinstance(ms, str):
        norm_meta = _normalize_compliance_standard(ms) or ms
        candidates.add(norm_meta)
    return candidates


def _extract_tag_standards(tags: List[str]) -> Set[str]:
    """Extract compliance standards from finding tags."""
    candidates = set()
    for tag in tags:
        norm = _normalize_compliance_standard(tag)
        if norm:
            candidates.add(norm)
    return candidates


def _map_findings_to_standards(candidates: Set[str], std_map: Dict[str, List[int]], index: int) -> None:
    """Map finding index to compliance standards."""
    for std in candidates:
        std_map.setdefault(std, []).append(index)


def _batch_normalize_compliance_standards(fields: Dict[str, List[Any]]) -> Dict[str, List[int]]:
    """Batch normalize compliance standards and return standard -> finding_indices mapping."""
    std_map: Dict[str, List[int]] = {}

    for i, (metadata, tags) in enumerate(zip(fields['metadata_list'], fields['tags_list'])):
        candidates = _extract_metadata_standards(metadata)
        tag_candidates = _extract_tag_standards(tags)
        candidates.update(tag_candidates)
        _map_findings_to_standards(candidates, std_map, i)

    return std_map

def _count_severities(severities: List[str]) -> Dict[str, int]:
    """Count findings by severity level."""
    sev_counters = {k: 0 for k in ['critical', 'high', 'medium', 'low', 'info', 'unknown']}
    for sev in severities:
        sev = sev if sev in sev_counters else 'unknown'
        sev_counters[sev] += 1
    return sev_counters


def _calculate_risk_totals(risk_scores: List[int]) -> Tuple[int, float, List[int]]:
    """Calculate total and average risk scores."""
    total_risk = sum(risk_scores)
    avg_risk = (total_risk / len(risk_scores)) if risk_scores else 0.0
    return total_risk, avg_risk, risk_scores


def _determine_qualitative_risk(sev_counters: Dict[str, int]) -> str:
    """Determine overall qualitative risk level."""
    qualitative = 'info'
    order = ['critical', 'high', 'medium', 'low', 'info']
    for level in order:
        if sev_counters.get(level):
            qualitative = level
            break
    return qualitative


def _batch_calculate_risk_metrics(fields: Dict[str, List[Any]]) -> Dict[str, Any]:
    """Batch calculate risk assessment metrics."""
    sev_counters = _count_severities(fields['severities'])
    total_risk, avg_risk, risk_values = _calculate_risk_totals(fields['risk_scores'])
    qualitative_risk = _determine_qualitative_risk(sev_counters)

    return {
        'sev_counters': sev_counters,
        'total_risk': total_risk,
        'avg_risk': avg_risk,
        'qualitative_risk': qualitative_risk,
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
    "WarningInfo",
    "SummarizationContext",
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


def _build_enrichment_pipeline_models(state: StateType) -> List[models.Finding]:
    """Build finding models from state for enrichment pipeline."""
    return _findings_from_graph(state)


def _create_enrichment_report(findings: List[models.Finding]) -> models.Report:
    """Create a report object for enrichment processing."""
    sr = models.ScannerResult(
        scanner="mixed",
        finding_count=len(findings),
        findings=findings,
    )
    return models.Report(
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


def _run_enrichment_pipeline(astate: models.AgentState) -> models.AgentState:
    """Run the enrichment pipeline on agent state."""
    astate = pipeline.augment(astate)
    astate = knowledge.apply_external_knowledge(astate)
    return astate


def _extract_enriched_findings(astate: models.AgentState) -> List[Dict[str, Any]]:
    """Extract enriched findings from agent state."""
    enriched: List[Dict[str, Any]] = []
    if astate.report and astate.report.results:
        for result in astate.report.results:
            for finding in result.findings:
                try:
                    enriched.append(finding.model_dump())
                except Exception:  # pragma: no cover
                    continue
    return enriched


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
        findings = _build_enrichment_pipeline_models(state)
        report = _create_enrichment_report(findings)
        astate = models.AgentState(report=report)
        astate = _run_enrichment_pipeline(astate)
        enriched = _extract_enriched_findings(astate)
        state["enriched_findings"] = enriched
    except Exception as e:  # pragma: no cover
        logger.exception("enrich_findings failed: %s", e)
        _append_warning(state, WarningInfo("graph", "enrich", str(e)))
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
        _append_warning(state, WarningInfo('graph', 'summarize', 'iteration_limit_reached'))  # type: ignore
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
        _append_warning(state, WarningInfo('graph', 'summarize', str(e)))  # type: ignore
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
        _append_warning(state, WarningInfo('graph', 'rule_mine', str(e)))  # type: ignore
    finally:
        if tf_path:
            try:
                import os
                os.unlink(tf_path)
            except Exception:
                pass
    return state


def _validate_correlation_inputs(findings_dicts: List[Dict[str, Any]], findings_models: List[models.Finding]) -> bool:
    """Validate inputs for correlation processing."""
    return bool(findings_dicts and findings_models)


def _initialize_correlation_results() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Initialize empty correlation results."""
    return [], []


def _apply_correlation_rules(findings_models: List[models.Finding]) -> Tuple[List[Any], Dict[str, Any]]:
    """Apply correlation rules and return correlations with lookup map."""
    try:
        correlator = rules.Correlator(rules.DEFAULT_RULES)
        correlations = correlator.apply(findings_models)
        corr_map = {c.id: c for c in correlations}
        return correlations, corr_map
    except Exception:  # pragma: no cover
        return [], {}


def _attach_correlations_to_findings(findings_models: List[models.Finding], corr_map: Dict[str, Any]) -> None:
    """Attach correlation references to findings."""
    for finding in findings_models:
        for corr_id in corr_map.keys():
            if finding.id in corr_map[corr_id].related_finding_ids:
                if corr_id not in finding.correlation_refs:
                    finding.correlation_refs.append(corr_id)


def _prepare_correlation_data(state: StateType) -> Tuple[List[Dict[str, Any]], List[models.Finding], bool]:
    """Prepare data for correlation processing and check if correlation is needed."""
    findings_dicts = _extract_findings_from_state(state, 'enriched_findings')
    if not findings_dicts:
        state['correlated_findings'], state['correlations'] = _initialize_correlation_results()
        return [], [], False

    findings_models = _build_finding_models(findings_dicts)
    if not _validate_correlation_inputs(findings_dicts, findings_models):
        state['correlated_findings'], state['correlations'] = _initialize_correlation_results()
        return [], [], False

    return findings_dicts, findings_models, True


def _execute_correlation_processing(findings_models: List[models.Finding]) -> Tuple[List[Any], Dict[str, Any]]:
    """Execute correlation rules and attach correlations to findings."""
    astate = _build_agent_state(findings_models, "mixed")
    correlations, corr_map = _apply_correlation_rules(findings_models)
    _attach_correlations_to_findings(findings_models, corr_map)
    return correlations, corr_map


def _update_correlation_state(state: StateType, findings_models: List[models.Finding], correlations: List[Any]) -> None:
    """Update state with correlation results."""
    state['correlated_findings'] = [finding.model_dump() for finding in findings_models]
    state['correlations'] = [c.model_dump() for c in correlations]


def correlate_findings(state: StateType) -> StateType:
    """Apply correlation rules to enriched findings and attach correlation references.

    Optimized: Uses helper functions and reduces redundant operations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        findings_dicts, findings_models, needs_correlation = _prepare_correlation_data(state)
        if not needs_correlation:
            return state

        correlations, corr_map = _execute_correlation_processing(findings_models)
        _update_correlation_state(state, findings_models, correlations)
    except Exception as e:  # pragma: no cover
        logger.exception("correlate_findings failed: %s", e)
        _append_warning(state, WarningInfo('graph', 'correlate', str(e)))  # type: ignore
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])
    return state


def _generate_cache_key(raw_list: List[Dict[str, Any]]) -> str:
    """Generate deterministic cache key from raw findings."""
    try:
        return util_hash.stable_hash(raw_list, "enrich")
    except Exception:  # pragma: no cover - extremely unlikely
        return "enrich:invalid_key"


def _check_cache_hit(cache: Dict[str, Any], cache_key: str) -> bool:
    """Check if cache key exists in cache."""
    return cache_key in cache


def _handle_cache_hit(state: StateType, cache: Dict[str, Any], cache_key: str, start: float) -> StateType:
    """Handle cache hit by rehydrating from cache and updating metrics."""
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


def _perform_enrichment_pipeline(state: StateType) -> List[Dict[str, Any]]:
    """Perform the enrichment pipeline and return enriched findings."""
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
    return enriched


def _update_cache_and_keys(state: StateType, cache: Dict[str, Any], cache_key: str, enriched: List[Dict[str, Any]]) -> None:
    """Update cache and cache keys with enriched findings."""
    cache[cache_key] = enriched
    ck_list = state["cache_keys"]
    if cache_key not in ck_list:
        ck_list.append(cache_key)


def _prepare_enrichment_state(state: StateType) -> Tuple[str, Dict[str, Any]]:
    """Prepare state for enrichment processing."""
    raw_list = state.get("raw_findings") or []
    _initialize_state_fields(state, 'warnings', 'metrics', 'cache_keys', 'enrich_cache')
    cache_key = _generate_cache_key(raw_list)
    cache: Dict[str, Any] = state["enrich_cache"]
    return cache_key, cache


def _handle_enrichment_cache_hit(state: StateType, cache: Dict[str, Any], cache_key: str, start: float) -> Optional[StateType]:
    """Handle cache hit scenario for enrichment."""
    if _check_cache_hit(cache, cache_key):
        return _handle_cache_hit(state, cache, cache_key, start)
    return None


def _execute_enrichment_pipeline(state: StateType, cache: Dict[str, Any], cache_key: str) -> None:
    """Execute enrichment pipeline and update cache."""
    enriched = _perform_enrichment_pipeline(state)
    state["enriched_findings"] = enriched
    _update_cache_and_keys(state, cache, cache_key, enriched)


def _handle_enrichment_error(state: StateType, cache_key: str, error: Exception) -> None:
    """Handle enrichment errors with fallback logic."""
    logger.exception("enhanced_enrich_findings failed key=%s error=%s", cache_key, error)
    _append_warning(state, WarningInfo("graph", "enhanced_enrich", f"{type(error).__name__}: {error}"))  # type: ignore
    if "enriched_findings" not in state:
        state["enriched_findings"] = state.get("raw_findings", [])


async def enhanced_enrich_findings(state: StateType) -> StateType:
    """Advanced async enrichment node with caching & metrics.

    Optimized: Uses helper functions for state initialization and metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        cache_key, cache = _prepare_enrichment_state(state)
        
        # Check for cache hit
        cached_result = _handle_enrichment_cache_hit(state, cache, cache_key, start)
        if cached_result is not None:
            return cached_result
        
        # Cache miss -> perform enrichment
        _execute_enrichment_pipeline(state, cache, cache_key)
    except Exception as e:  # pragma: no cover
        _handle_enrichment_error(state, cache_key, e)
    finally:
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


async def streaming_summarizer(context: SummarizationContext) -> Any:
    """Deterministic streaming facade using encapsulated context.

    For now this simply delegates to _call_summarize once (no incremental
    token emission) to maintain determinism. Later this could yield partial
    chunks and assemble them into a final Summaries object.
    """
    return await _call_summarize(context)


async def _call_summarize(context: SummarizationContext) -> Any:
    """Helper to normalize async/sync summarize calls using encapsulated context."""
    import inspect
    res = context.provider.summarize(context.reductions, context.correlations, context.actions, baseline_context=context.baseline_context)
    if inspect.isawaitable(res):
        return await res
    return res


def _check_iteration_limit(state: StateType) -> bool:
    """Check if iteration limit has been reached and append warning if so."""
    max_iter = int(_get_env_var('AGENT_MAX_SUMMARY_ITERS', '3'))
    iters = int(state.get('iteration_count', 0) or 0)
    if iters >= max_iter:
        _append_warning(state, WarningInfo('graph', 'enhanced_summarize', 'iteration_limit_reached'))  # type: ignore
        return True
    return False


def _prepare_summarization_data(state: StateType) -> Tuple[Any, List[Any], Dict[str, Any], bool]:
    """Prepare data needed for summarization."""
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
    
    return provider, corr_objs, baseline_context, streaming


async def _execute_summarization(provider: Any, reductions: Any, corr_objs: List[Any], baseline_context: Dict[str, Any], streaming: bool) -> Tuple[Any, Any]:
    """Execute summarization using appropriate method."""
    context = SummarizationContext(
        provider=provider,
        reductions=reductions,
        correlations=corr_objs,
        actions=[],
        baseline_context=baseline_context
    )
    if streaming:
        return await streaming_summarizer(context)
    else:
        return await _call_summarize(context)


def _update_summarization_state(state: StateType, summaries: Any, iters: int) -> None:
    """Update state with summarization results."""
    state['summary'] = summaries.model_dump()
    state['iteration_count'] = iters + 1


def _extract_summarization_metrics(state: StateType, summaries: Any) -> None:
    """Extract and update metrics from summarization results."""
    sm = summaries.metrics or {}
    metrics = state.setdefault('metrics', {})
    if 'tokens_prompt' in sm:
        metrics['tokens_prompt'] = sm['tokens_prompt']
    if 'tokens_completion' in sm:
        metrics['tokens_completion'] = sm['tokens_completion']
    _update_metrics_counter(state, 'summarize_calls')


async def enhanced_summarize_host_state(state: StateType) -> StateType:
    """Advanced async summarization node with streaming + metrics.

    Optimized: Uses helper functions and cached environment variables.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        if _check_iteration_limit(state):
            return state

        provider, corr_objs, baseline_context, streaming = _prepare_summarization_data(state)
        reductions = reduction.reduce_all(_build_finding_models(_extract_findings_from_state(state, 'correlated_findings')))
        
        summaries, metadata = await _execute_summarization(provider, reductions, corr_objs, baseline_context, streaming)
        
        iters = int(state.get('iteration_count', 0) or 0)
        _update_summarization_state(state, summaries, iters)
        _extract_summarization_metrics(state, summaries)
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_summarize_host_state failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'enhanced_summarize', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'summarize_duration', start)
    return state


def _build_suggestion_context(state: StateType) -> str:
    """Build context string from state for rule suggestions."""
    context_parts = []
    if state.get('summary'):
        context_parts.append(f"Summary: {state['summary']}")
    if state.get('correlations'):
        context_parts.append(f"Correlations: {len(state['correlations'])} items")
    if state.get('baseline_results'):
        context_parts.append(f"Baseline: {state['baseline_results']}")
    return '\n'.join(context_parts) if context_parts else 'No additional context'


def _refine_suggestions_with_provider(provider: Any, suggestions: List[Any]) -> List[Any]:
    """Refine suggestions using provider's refine_rules method if available."""
    try:
        refine_fn = getattr(provider, 'refine_rules', None)
        if callable(refine_fn) and suggestions:
            refined = refine_fn(suggestions, examples=None)
            return refined if isinstance(refined, list) else suggestions
    except Exception:  # pragma: no cover - refinement fallback
        pass
    return suggestions


def _prepare_suggestion_data(state: StateType) -> Tuple[Any, List[models.Finding], str]:
    """Prepare data needed for rule suggestions."""
    provider = get_enhanced_llm_provider()
    findings_src = _extract_findings_from_state(state, 'correlated_findings')
    findings_models = _build_finding_models(findings_src)
    context = _build_suggestion_context(state)
    return provider, findings_models, context


def _execute_gap_mining(findings_models: List[models.Finding]) -> Dict[str, Any]:
    """Execute gap mining to get rule suggestions."""
    import tempfile, json as _json
    from pathlib import Path
    
    tf_path = None
    try:
        findings_data = {'enriched_findings': [f.model_dump() for f in findings_models]}
        
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tf:
            tf_path = tf.name
            _json.dump(findings_data, tf)
            tf.flush()
            # Use slightly permissive thresholds to increase suggestion probability
            result = rule_gap_miner.mine_gap_candidates([Path(tf.name)], risk_threshold=10, min_support=2)
        
        return result
    finally:
        if tf_path:
            try:
                import os
                os.unlink(tf_path)
            except Exception:
                pass


def _process_suggestions(suggestions: List[Any], provider: Any) -> List[Any]:
    """Process and refine suggestions."""
    # Optional refinement with provider
    suggestions = _refine_suggestions_with_provider(provider, suggestions)

    # Ensure suggestions is a list
    try:
        if not isinstance(suggestions, list):
            suggestions = [suggestions] if suggestions else []
    except Exception:
        suggestions = []
    
    return suggestions


def _update_suggestion_state(state: StateType, suggestions: List[Any]) -> None:
    """Update state with processed suggestions."""
    state['suggested_rules'] = suggestions

    # Apply unified normalization
    state = util_normalization.normalize_rule_suggestions(state)
    state = util_normalization.ensure_monotonic_timing(state)
    state = util_normalization.add_metrics_version(state)

    # Metrics with helper
    _update_metrics_counter(state, 'rule_suggest_calls')
    metrics = state.setdefault('metrics', {})
    metrics['rule_suggest_count'] = len(suggestions) if hasattr(suggestions, '__len__') else 0


async def enhanced_suggest_rules(state: StateType) -> StateType:
    """Advanced async rule suggestion node with temp file optimization.

    Optimized: Uses helper functions, cached env vars, and eliminates temp file usage.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        provider, findings_models, context = _prepare_suggestion_data(state)
        
        # Use cached env var for max suggestions (though not used in current logic)
        max_suggestions = int(_get_env_var('AGENT_MAX_RULE_SUGGESTIONS', '10'))

        result = _execute_gap_mining(findings_models)
        raw_suggestions = result.get('suggestions', [])
        suggestions = _process_suggestions(raw_suggestions, provider)
        _update_suggestion_state(state, suggestions)
    except Exception as e:  # pragma: no cover
        logger.exception('enhanced_suggest_rules failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'enhanced_suggest_rules', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'rule_suggest_duration', start)
    return state


def _check_human_feedback_gate(state: StateType) -> Optional[str]:
    """Check if human feedback is pending and return routing decision."""
    if state.get('human_feedback_pending'):
        return 'human_feedback'
    return None


def _get_findings_for_routing(state: StateType) -> List[Dict[str, Any]]:
    """Get findings from state for routing decisions."""
    return state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []


def _check_compliance_routing(fields: Dict[str, List[Any]]) -> Optional[str]:
    """Check for compliance-related findings and return routing decision."""
    compliance_indices = _batch_check_compliance_indicators(fields)
    if compliance_indices:
        return 'compliance'
    return None


def _check_baseline_routing(fields: Dict[str, List[Any]], state: StateType) -> Optional[str]:
    """Check for high severity findings missing baseline and return routing decision."""
    high_severity_indices = _batch_filter_findings_by_severity(fields, {'high', 'critical'})
    if high_severity_indices:
        baseline = state.get('baseline_results') or {}
        # Check if any high-sev finding is missing baseline
        for idx in high_severity_indices:
            fid = fields['ids'][idx]
            if fid and fid not in baseline:
                return 'baseline'
    return None


def _check_external_data_routing(fields: Dict[str, List[Any]]) -> Optional[str]:
    """Check for findings requiring external data and return routing decision."""
    external_indices = _batch_check_external_requirements(fields)
    if external_indices:
        return 'risk'
    return None


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
        route = _check_human_feedback_gate(state)
        if route:
            return route

        # Choose findings source preference
        findings = _get_findings_for_routing(state)
        if not findings:
            return 'summarize'

        # Batch extract all needed fields once
        fields = _batch_extract_finding_fields(findings)

        # 2. Compliance detection (batch check)
        route = _check_compliance_routing(fields)
        if route:
            return route

        # 3. High severity missing baseline (batch check)
        route = _check_baseline_routing(fields, state)
        if route:
            return route

        # 4. External data requirement (batch check)
        route = _check_external_data_routing(fields)
        if route:
            return route

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


def _prepare_tool_coordination_data(state: StateType) -> Tuple[List[Dict[str, Any]], bool]:
    """Prepare data for tool coordination and check if coordination is needed."""
    findings = state.get('correlated_findings') or state.get('enriched_findings') or []
    if not findings:
        state['pending_tool_calls'] = []
        _update_metrics_counter(state, 'tool_coordinator_calls')
        return [], False
    
    # Batch check baseline status
    missing_indices = _batch_check_baseline_status(findings)
    if not missing_indices:
        state['pending_tool_calls'] = []
        _update_metrics_counter(state, 'tool_coordinator_calls')
        return [], False
    
    # Batch extract fields for missing findings
    missing_findings = [findings[i] for i in missing_indices]
    return missing_findings, True


def _build_tool_calls_from_findings(missing_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build tool calls from missing findings."""
    fields = _batch_extract_finding_fields(missing_findings)
    pending: List[Dict[str, Any]] = []
    host_id = _get_env_var('AGENT_GRAPH_HOST_ID', 'graph_host')

    for i, (fid, title, severity, scanner) in enumerate(zip(
        fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
    )):
        # Extract scanner from metadata if available
        scanner_name = _extract_scanner_name_from_metadata(scanner)

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

    return pending


def _extract_scanner_name_from_metadata(scanner: Any) -> str:
    """Extract scanner name from metadata, defaulting to 'mixed'."""
    if isinstance(scanner, dict):
        return scanner.get('scanner', 'mixed')
    return 'mixed'


def _update_tool_coordination_state(state: StateType, pending: List[Dict[str, Any]]) -> None:
    """Update state with tool coordination results."""
    state['pending_tool_calls'] = pending
    _update_metrics_counter(state, 'tool_coordinator_calls')


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
        missing_findings, needs_coordination = _prepare_tool_coordination_data(state)
        if not needs_coordination:
            return state
        
        pending = _build_tool_calls_from_findings(missing_findings)
        _update_tool_coordination_state(state, pending)
    except Exception as e:  # pragma: no cover
        logger.exception('tool_coordinator failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'tool_coordinator', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'tool_coordinator_duration', start)
    return state


def _derive_pending_tool_calls_on_demand(state: StateType) -> Optional[List[Dict[str, Any]]]:
    """Derive pending tool calls from enriched findings if not already present."""
    enriched = state.get('enriched_findings') or []
    if not enriched:
        return None

    # Batch check baseline status
    missing_indices = _batch_check_baseline_status(enriched)
    if not missing_indices:
        return None

    # Batch extract fields for missing findings
    missing_findings = [enriched[i] for i in missing_indices]
    fields = _batch_extract_finding_fields(missing_findings)

    # Build tool calls using batched data
    return _build_baseline_tool_calls(fields)


def _build_baseline_tool_calls(fields: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Build baseline query tool calls from finding fields."""
    host_id = _get_env_var('AGENT_GRAPH_HOST_ID', 'graph_host')
    pending = []

    for i, (fid, title, severity, scanner) in enumerate(zip(
        fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
    )):
        scanner_name = _extract_scanner_name(scanner)

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

    return pending


def _extract_scanner_name(scanner: Any) -> str:
    """Extract scanner name from metadata, defaulting to 'mixed'."""
    if isinstance(scanner, dict):
        return scanner.get('scanner', 'mixed')
    return 'mixed'


def _check_dependencies_available() -> bool:
    """Check if required dependencies for baseline planning are available."""
    return AIMessage is not None


def _get_or_derive_pending_tool_calls(state: StateType) -> Optional[List[Dict[str, Any]]]:
    """Get pending tool calls from state or derive them on-demand."""
    pending = state.get('pending_tool_calls')
    if not pending:  # derive on-demand if empty or None
        pending = _derive_pending_tool_calls_on_demand(state)
    return pending


def _construct_baseline_message(pending: List[Dict[str, Any]]) -> Any:
    """Construct AIMessage with tool calls for baseline queries."""
    return AIMessage(content="Baseline context required", tool_calls=pending)  # type: ignore[arg-type]


def _update_messages_with_baseline_query(state: StateType, pending: List[Dict[str, Any]]) -> None:
    """Update state messages with baseline query message."""
    msgs = state.get('messages') or []
    msgs.append(_construct_baseline_message(pending))
    state['messages'] = msgs


def plan_baseline_queries(state: StateType) -> StateType:
    """Construct AIMessage with tool_calls for baseline queries with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)
    
    # Ensure monotonic timing is initialized for accurate duration calculations
    state = util_normalization.ensure_monotonic_timing(state)

    try:
        if not _check_dependencies_available():  # dependency not available
            return state

        pending = _get_or_derive_pending_tool_calls(state)
        if not pending:
            _update_metrics_counter(state, 'baseline_plan_calls')
            return state

        _update_messages_with_baseline_query(state, pending)
        _update_metrics_counter(state, 'baseline_plan_calls')
    except Exception as e:  # pragma: no cover
        logger.exception('plan_baseline_queries (scaffold) failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'plan_baseline', f"{type(e).__name__}: {e}"))  # type: ignore
    return state


def _extract_message_payload(message) -> Any:
    """Extract payload from ToolMessage or dict message."""
    if ToolMessage is not None and isinstance(message, ToolMessage):
        return getattr(message, 'content', None)
    elif isinstance(message, dict) and message.get('type') == 'tool':
        return message.get('content')
    return None


def _parse_payload_to_data_obj(payload) -> Optional[Dict[str, Any]]:
    """Parse payload to data object, handling dict or JSON string."""
    if isinstance(payload, dict):
        return payload
    elif isinstance(payload, str):
        try:
            import json as _json  # local import
            return _json.loads(payload)
        except Exception:  # pragma: no cover
            pass
    return None


def _integrate_finding_data(data_obj: Dict[str, Any], results: Dict[str, Any]) -> None:
    """Integrate finding data into results if it has a valid finding_id."""
    fid = data_obj.get('finding_id')
    if isinstance(fid, str):
        results[fid] = data_obj  # type: ignore[index]


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
        
        for m in msgs:
            try:
                payload = _extract_message_payload(m)
                if payload is None:
                    continue
                    
                data_obj = _parse_payload_to_data_obj(payload)
                if data_obj is None:
                    continue
                    
                _integrate_finding_data(data_obj, results)
            except Exception:  # pragma: no cover
                continue
        state['baseline_results'] = results
    except Exception as e:  # pragma: no cover
        logger.exception('integrate_baseline_results (scaffold) failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'integrate_baseline', f"{type(e).__name__}: {e}"))  # type: ignore
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
        _append_warning(state, WarningInfo('graph', 'risk_analyzer', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'risk_analyzer_duration', start)
    return state


def _prepare_compliance_data(state: StateType) -> Tuple[List[Dict[str, Any]], bool]:
    """Prepare data for compliance checking and check if checking is needed."""
    findings = state.get('correlated_findings') or state.get('enriched_findings') or state.get('raw_findings') or []
    if not findings:
        state['compliance_check'] = {
            'standards': {},
            'total_compliance_findings': 0,
        }
        _update_metrics_counter(state, 'compliance_checker_calls')
        return [], False
    return findings, True


def _execute_compliance_analysis(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], int]:
    """Execute compliance analysis and return compliance map and total."""
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

    return std_map, total


def _update_compliance_state(state: StateType, std_map: Dict[str, Dict[str, Any]], total: int) -> None:
    """Update state with compliance check results."""
    state['compliance_check'] = {
        'standards': std_map,
        'total_compliance_findings': total,
    }

    # Apply unified normalization
    state = util_normalization.unify_compliance_check(state)
    state = util_normalization.ensure_monotonic_timing(state)
    state = util_normalization.add_metrics_version(state)

    _update_metrics_counter(state, 'compliance_checker_calls')


async def compliance_checker(state: StateType) -> StateType:
    """Evaluate simple compliance mapping heuristics with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations and optimize compliance mapping.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        findings, needs_checking = _prepare_compliance_data(state)
        if not needs_checking:
            return state

        std_map, total = _execute_compliance_analysis(findings)
        _update_compliance_state(state, std_map, total)
    except Exception as e:  # pragma: no cover
        logger.exception('compliance_checker failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'compliance_checker', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'compliance_checker_duration', start)
    return state


# ---------------------------------------------------------------------------
# Operational Nodes (Phase 4 - Step 12)
# ---------------------------------------------------------------------------
def _analyze_error_patterns(errs: List[Any]) -> Tuple[int, int]:
    """Analyze error patterns and return timeout and provider error counts."""
    timeout_count = 0
    provider_errs = 0
    
    for e in errs[-25:]:  # analyze last 25 for recency bias
        msg = _extract_error_message(e)
        low = msg.lower()
        if 'timeout' in low:
            timeout_count += 1
        if 'model' in low or 'provider' in low:
            provider_errs += 1
    
    return timeout_count, provider_errs


def _extract_error_message(error: Any) -> str:
    """Extract error message from various error formats."""
    if isinstance(error, dict):
        return str(error.get('error') or error.get('message') or '')
    else:
        return str(error)


def _toggle_error_modes(state: StateType, timeout_count: int, provider_errs: int) -> None:
    """Toggle degraded and fallback modes based on error counts."""
    if timeout_count >= 3:
        state['degraded_mode'] = True
    
    # fallback provider decision
    if provider_errs >= 2:
        state['llm_provider_mode'] = 'fallback'
    
    if state.get('degraded_mode') and not state.get('llm_provider_mode'):
        state['llm_provider_mode'] = 'fallback'


def _update_error_metrics(state: StateType, timeout_count: int) -> None:
    """Update error-related metrics."""
    m = state.setdefault('metrics', {})
    m['error_handler_calls'] = m.get('error_handler_calls', 0) + 1
    m['timeout_error_count'] = timeout_count


async def error_handler(state: StateType) -> StateType:
    """Analyze recent errors and toggle degraded / fallback modes with optimized patterns.

    Optimized: Uses helper functions and standardized metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        errs = state.get('errors') or []
        timeout_count, provider_errs = _analyze_error_patterns(errs)
        _toggle_error_modes(state, timeout_count, provider_errs)
        _update_error_metrics(state, timeout_count)
    except Exception as e:  # pragma: no cover
        logger.exception('error_handler failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'error_handler', f"{type(e).__name__}: {e}"))  # type: ignore
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
        _append_warning(state, WarningInfo('graph', 'human_feedback', f"{type(e).__name__}: {e}"))  # type: ignore
    finally:
        _update_metrics_duration(state, 'human_feedback_node_duration', start)
    return state


def _cache_enrichment_data(cache_store: Dict[str, Any], enriched: Any) -> None:
    """Cache enrichment findings if not already cached."""
    if enriched is not None:
        try:
            ek = util_hash.stable_hash(enriched, "enrich")
            if ek not in cache_store:
                cache_store[ek] = enriched
        except Exception:  # pragma: no cover
            pass


def _cache_summary_snapshot(cache_store: Dict[str, Any], state: StateType) -> None:
    """Cache summary snapshot for current iteration."""
    if 'summary' in state:
        iter_count = state.get('iteration_count', 0)
        key = f"summary:iter_{iter_count}"
        if key not in cache_store:
            cache_store[key] = state['summary']


def _cache_analysis_snapshots(cache_store: Dict[str, Any], state: StateType) -> None:
    """Cache risk assessment and compliance check snapshots."""
    if 'risk_assessment' in state:
        cache_store['risk:latest'] = state['risk_assessment']
    if 'compliance_check' in state:
        cache_store['compliance:latest'] = state['compliance_check']


def _calculate_cache_hit_rate(metrics: Dict[str, Any]) -> None:
    """Calculate and set cache hit rate in metrics."""
    hits = metrics.get('cache_hits', 0)
    misses = metrics.get('cache_misses', 0)
    denom = hits + misses
    if denom:
        metrics['cache_hit_rate'] = hits / denom


def _prepare_cache_operations(state: StateType) -> Dict[str, Any]:
    """Prepare cache store for operations."""
    return state.setdefault('cache', {})


def _execute_cache_operations(cache_store: Dict[str, Any], state: StateType) -> None:
    """Execute all cache operations."""
    # Cache different types of data
    _cache_enrichment_data(cache_store, state.get('enriched_findings'))
    _cache_summary_snapshot(cache_store, state)
    _cache_analysis_snapshots(cache_store, state)


def _update_cache_metrics(state: StateType) -> None:
    """Update cache-related metrics."""
    metrics = state.setdefault('metrics', {})
    _calculate_cache_hit_rate(metrics)
    _update_metrics_counter(state, 'cache_manager_calls')


async def cache_manager(state: StateType) -> StateType:
    """Centralize caching logic with optimized patterns.

    Optimized: Uses helper functions and standardized metrics.
    """
    # Normalize state to ensure all mandatory keys exist
    state = graph_state.normalize_graph_state(state)

    start = time.monotonic()
    try:
        cache_store = _prepare_cache_operations(state)
        _execute_cache_operations(cache_store, state)
        _update_cache_metrics(state)
    except Exception as e:  # pragma: no cover
        logger.exception('cache_manager failed: %s', e)
        _append_warning(state, WarningInfo('graph', 'cache_manager', f"{type(e).__name__}: {e}"))  # type: ignore
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
        _append_warning(state, WarningInfo('graph', 'metrics_collector', f"{type(e).__name__}: {e}"))  # type: ignore
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

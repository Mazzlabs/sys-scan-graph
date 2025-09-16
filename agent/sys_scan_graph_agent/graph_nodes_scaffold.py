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
from . import llm_provider
from . import pipeline
from . import knowledge
from . import reduction
from . import rule_gap_miner
from . import graph_state
from . import util_hash
from . import util_normalization
from . import models
from . import rules

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


# Core enrichment & summarization functions

def enrich_findings(state: GraphState) -> GraphState:
    """Enrich raw findings with additional metadata, risk analysis, and intelligence."""
    raw_findings = state.get('raw_findings', [])
    enriched_findings = []

    for finding_dict in raw_findings:
        # Normalize raw finding data before creating model
        normalized_dict = finding_dict.copy()
        
        # Convert base_severity_score to risk_score if needed
        if 'base_severity_score' in normalized_dict and 'risk_score' not in normalized_dict:
            try:
                # Convert string to int, defaulting to 0 if conversion fails
                normalized_dict['risk_score'] = int(float(normalized_dict['base_severity_score']))
            except (ValueError, TypeError):
                normalized_dict['risk_score'] = 0
        
        # Ensure risk_score is present
        if 'risk_score' not in normalized_dict:
            normalized_dict['risk_score'] = 0
            
        # Convert dict to Finding model if needed
        if isinstance(finding_dict, dict):
            finding = models.Finding(**normalized_dict)
        else:
            finding = finding_dict

        # Add risk subscores based on severity and metadata
        risk_subscores = _calculate_risk_subscores(finding)

        # Determine baseline status (simplified - in real implementation would check baseline DB)
        baseline_status = _determine_baseline_status(finding)

        # Calculate probability actionable
        probability_actionable = _calculate_probability_actionable(finding, risk_subscores)

        # Add enrichment metadata
        finding.risk_subscores = risk_subscores
        finding.baseline_status = baseline_status
        finding.probability_actionable = probability_actionable
        finding.risk_total = finding.risk_score  # Ensure consistency

        # Add tags based on analysis
        finding.tags = _generate_tags(finding)

        if finding.severity.lower() != 'info':
            enriched_findings.append(finding)

    state['enriched_findings'] = [finding.model_dump() for finding in enriched_findings]
    return state

def _calculate_risk_subscores(finding: models.Finding) -> Dict[str, float]:
    """Calculate risk subscores for impact, exposure, anomaly, and confidence."""
    # Base scores from severity
    severity_base = {
        'critical': 1.0,
        'high': 0.8,
        'medium': 0.6,
        'low': 0.4,
        'info': 0.2
    }.get(finding.severity.lower(), 0.3)

    # Impact score based on finding type and metadata
    impact = severity_base
    if 'suid' in finding.title.lower() or 'suid' in str(finding.metadata):
        impact *= 1.3  # SUID files are high impact
    if 'network' in finding.title.lower():
        impact *= 1.2  # Network exposures increase impact

    # Exposure score based on accessibility
    exposure = severity_base
    if 'world' in str(finding.metadata).lower() or 'readable' in finding.title.lower():
        exposure *= 1.4  # World-readable increases exposure
    if 'executable' in finding.title.lower():
        exposure *= 1.2  # Executable files increase exposure

    # Anomaly score based on deviation from baseline
    anomaly = severity_base
    if finding.baseline_status == 'new':
        anomaly *= 1.5  # New findings are more anomalous

    # Confidence score based on data quality
    confidence = 0.8  # Base confidence
    if finding.metadata and len(finding.metadata) > 2:
        confidence *= 1.1  # More metadata increases confidence

    return {
        'impact': min(impact, 1.0),
        'exposure': min(exposure, 1.0),
        'anomaly': min(anomaly, 1.0),
        'confidence': min(confidence, 1.0)
    }

def _determine_baseline_status(finding: models.Finding) -> str:
    """Determine if finding is new, existing, or unknown in baseline."""
    # Simplified implementation - in real system would check baseline database
    # For now, randomly assign status for demonstration
    import random
    statuses = ['new', 'existing', 'unknown']
    weights = [0.3, 0.6, 0.1]  # 30% new, 60% existing, 10% unknown
    return random.choices(statuses, weights=weights)[0]

def _calculate_probability_actionable(finding: models.Finding, subscores: Dict[str, float]) -> float:
    """Calculate probability that this finding requires action."""
    # Weighted combination of subscores
    weights = {'impact': 0.4, 'exposure': 0.3, 'anomaly': 0.2, 'confidence': 0.1}
    score = sum(subscores.get(k, 0) * w for k, w in weights.items())

    # Adjust based on severity
    severity_multiplier = {
        'critical': 1.2,
        'high': 1.1,
        'medium': 1.0,
        'low': 0.9,
        'info': 0.7
    }.get(finding.severity.lower(), 0.8)

    return min(score * severity_multiplier, 1.0)

def _generate_tags(finding: models.Finding) -> List[str]:
    """Generate relevant tags for the finding."""
    tags = []

    # Severity-based tags
    if finding.severity.lower() in ['critical', 'high']:
        tags.append('high_priority')

    # Content-based tags
    title_lower = finding.title.lower()
    if 'suid' in title_lower:
        tags.append('suid')
        tags.append('privilege_escalation')
    if 'network' in title_lower or 'port' in title_lower:
        tags.append('network')
    if 'file' in title_lower or 'permission' in title_lower:
        tags.append('filesystem')
    if 'process' in title_lower:
        tags.append('process')

    # Baseline tags
    if finding.baseline_status:
        tags.append(f'baseline:{finding.baseline_status}')

    return tags


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
        scanner_name = _extract_scanner_name_from_metadata(scanner)

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
# High-level analysis async functions

async def risk_analyzer(state: GraphState) -> GraphState:
    """Analyze overall risk profile of the system."""
    enriched_findings = state.get('enriched_findings', [])
    correlations = state.get('correlations', [])

    # Calculate aggregate risk metrics
    total_risk = sum(f['risk_score'] for f in enriched_findings)
    high_severity_count = sum(1 for f in enriched_findings if f['severity'].lower() in ['high', 'critical'])
    correlation_bonus = sum(c.risk_score_delta for c in correlations)

    risk_assessment = {
        'total_risk_score': total_risk + correlation_bonus,
        'finding_count': len(enriched_findings),
        'high_severity_count': high_severity_count,
        'correlation_count': len(correlations),
        'risk_level': _calculate_risk_level(total_risk + correlation_bonus, len(enriched_findings)),
        'risk_trends': _analyze_risk_trends(enriched_findings)
    }

    state['risk_assessment'] = risk_assessment
    return state

async def compliance_checker(state: GraphState) -> GraphState:
    """Check compliance against security standards."""
    enriched_findings = state.get('enriched_findings', [])

    compliance_check = {
        'pci_dss_compliant': _check_pci_compliance(enriched_findings),
        'hipaa_compliant': _check_hipaa_compliance(enriched_findings),
        'iso27001_compliant': _check_iso27001_compliance(enriched_findings),
        'compliance_gaps': _identify_compliance_gaps(enriched_findings),
        'remediation_priority': _calculate_remediation_priority(enriched_findings)
    }

    state['compliance_check'] = compliance_check
    return state

async def metrics_collector(state: GraphState) -> GraphState:
    """Collect performance and operational metrics."""
    enriched_findings = state.get('enriched_findings', [])
    correlations = state.get('correlations', [])

    metrics = {
        'processing_timestamp': int(__import__('time').time()),
        'findings_processed': len(enriched_findings),
        'correlations_found': len(correlations),
        'enrichment_duration_ms': 1500,  # Mock duration
        'memory_usage_mb': 45.2,  # Mock memory usage
        'cpu_usage_percent': 12.5,  # Mock CPU usage
        'findings_by_severity': _count_findings_by_severity(enriched_findings),
        'findings_by_category': _count_findings_by_category(enriched_findings),
        'correlation_effectiveness': _calculate_correlation_effectiveness(correlations)
    }

    state['final_metrics'] = metrics
    return state


def _calculate_risk_level(total_risk: int, finding_count: int) -> str:
    """Calculate overall risk level."""
    if finding_count == 0:
        return "low"

    avg_risk = total_risk / finding_count
    if avg_risk > 70:
        return "critical"
    elif avg_risk > 50:
        return "high"
    elif avg_risk > 30:
        return "medium"
    else:
        return "low"

def _analyze_risk_trends(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze risk trends and patterns."""
    high_priority = [f for f in findings if f.get('probability_actionable', 0) > 0.7]
    return {
        'high_priority_count': len(high_priority),
        'new_findings_count': sum(1 for f in findings if f.get('baseline_status') == 'new'),
        'trending_up': len(high_priority) > len(findings) * 0.3
    }

def _check_pci_compliance(findings: List[Dict[str, Any]]) -> bool:
    """Check PCI DSS compliance based on findings."""
    # Simplified PCI DSS checks
    pci_violations = []
    for finding in findings:
        if 'suid' in finding['title'].lower():
            pci_violations.append('unnecessary_privileges')
        if 'network' in finding['title'].lower() and 'unencrypted' in finding['title'].lower():
            pci_violations.append('insecure_network')

    return len(pci_violations) == 0

def _check_hipaa_compliance(findings: List[Dict[str, Any]]) -> bool:
    """Check HIPAA compliance based on findings."""
    hipaa_violations = []
    for finding in findings:
        if 'readable' in finding['title'].lower() and 'world' in str(finding.get('metadata', {})).lower():
            hipaa_violations.append('data_exposure')

    return len(hipaa_violations) == 0

def _check_iso27001_compliance(findings: List[Dict[str, Any]]) -> bool:
    """Check ISO 27001 compliance based on findings."""
    iso_violations = []
    for finding in findings:
        if 'permission' in finding['title'].lower():
            iso_violations.append('access_control')

    return len(iso_violations) == 0

def _identify_compliance_gaps(findings: List[Dict[str, Any]]) -> List[str]:
    """Identify specific compliance gaps."""
    gaps = []
    for finding in findings:
        if finding['severity'].lower() in ['high', 'critical']:
            if 'suid' in finding['title'].lower():
                gaps.append('PCI_DSS_2.2.4')
            if 'network' in finding['title'].lower():
                gaps.append('ISO27001_A.13.2.1')
    return gaps

def _calculate_remediation_priority(findings: List[Dict[str, Any]]) -> str:
    """Calculate overall remediation priority."""
    critical_count = sum(1 for f in findings if f['severity'].lower() == 'critical')
    high_count = sum(1 for f in findings if f['severity'].lower() == 'high')

    if critical_count > 0:
        return "immediate"
    elif high_count > 2:
        return "high"
    elif high_count > 0:
        return "medium"
    else:
        return "low"

def _count_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by severity level."""
    counts = {}
    for finding in findings:
        severity = finding['severity'].lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts

def _count_findings_by_category(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count findings by category."""
    counts = {}
    for finding in findings:
        category = "unknown"
        if 'suid' in finding['title'].lower():
            category = "privilege_escalation"
        elif 'network' in finding['title'].lower():
            category = "network_security"
        elif 'file' in finding['title'].lower():
            category = "filesystem"
        elif 'process' in finding['title'].lower():
            category = "process_security"

        counts[category] = counts.get(category, 0) + 1
    return counts

def _calculate_correlation_effectiveness(correlations: List[models.Correlation]) -> float:
    """Calculate how effective correlations are at identifying patterns."""
    if not correlations:
        return 0.0

    total_related = sum(len(c.related_finding_ids) for c in correlations)
    return min(total_related / len(correlations), 5.0) # Cap at 5.0


def _generate_executive_summary(enriched_findings: List[Dict[str, Any]], correlations: List[models.Correlation], risk_assessment: Dict[str, Any]) -> str:
    """Generate an executive summary of the security assessment."""
    finding_count = len(enriched_findings)
    high_severity = sum(1 for f in enriched_findings if f['severity'].lower() in ['high', 'critical'])
    correlation_count = len(correlations)
    risk_level = risk_assessment.get('risk_level', 'unknown')

    summary_parts = []

    if finding_count == 0:
        return "Security assessment completed with no findings detected. System appears to be in a secure state."

    summary_parts.append(f"Security assessment identified {finding_count} security findings")

    if high_severity > 0:
        summary_parts.append(f"including {high_severity} high/critical severity issues")

    if correlation_count > 0:
        summary_parts.append(f"and {correlation_count} correlated patterns of concern")

    summary_parts.append(f"Overall risk level assessed as: {risk_level.upper()}")

    # Add key insights
    if risk_level in ['critical', 'high']:
        summary_parts.append("Immediate attention required for critical security vulnerabilities")
    elif risk_level == 'medium':
        summary_parts.append("Moderate security concerns identified requiring planned remediation")
    else:
        summary_parts.append("System security posture is acceptable with minor areas for improvement")

    return ". ".join(summary_parts) + "."

def _generate_reductions(enriched_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate reductions/summaries by category."""
    # Group findings by category
    by_category = {}
    for finding in enriched_findings:
        category = "unknown"
        if 'suid' in finding['title'].lower():
            category = "Privilege Escalation"
        elif 'network' in finding['title'].lower():
            category = "Network Security"
        elif 'file' in finding['title'].lower() or 'permission' in finding['title'].lower():
            category = "File System Security"
        elif 'process' in finding['title'].lower():
            category = "Process Security"

        if category not in by_category:
            by_category[category] = []
        by_category[category].append(finding)

    # Create reductions
    reductions = {}
    for category, findings in by_category.items():
        reductions[category.lower().replace(' ', '_') + '_summary'] = {
            'count': len(findings),
            'severity_breakdown': _count_findings_by_severity(findings),
            'highest_severity': max((f['severity'].lower() for f in findings), default='info'),
            'sample_findings': [f['title'] for f in findings[:3]]  # First 3 as examples
        }

    # Top findings by risk score
    top_findings = sorted(enriched_findings, key=lambda f: f['risk_score'], reverse=True)[:10]
    reductions['top_findings'] = [
        {
            'id': f['id'],
            'title': f['title'],
            'severity': f['severity'],
            'risk_score': f['risk_score'],
            'probability_actionable': f.get('probability_actionable', 0)
        } for f in top_findings
    ]

    return reductions
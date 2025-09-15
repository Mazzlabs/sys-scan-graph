from __future__ import annotations
"""Graph node functions mapping high-level analysis steps onto GraphState.

These nodes operate on the lightweight dict-based GraphState (see graph.py)
while internally leveraging existing Pydantic model pipeline components.

They are intentionally defensive: if any underlying module raises, the node
captures the error as a warning entry and proceeds without aborting the graph.
"""
from typing import Any, List, Dict
import tempfile, json

import graph
import data_governance
import models
import knowledge
import pipeline
import reduction
import llm_provider
import rules
import rule_gap_miner
import graph_state
GraphState = graph.GraphState
get_data_governor = data_governance.get_data_governor
Finding = models.Finding
ScannerResult = models.ScannerResult
Report = models.Report
Meta = models.Meta
Summary = models.Summary
SummaryExtension = models.SummaryExtension
AgentState = models.AgentState
apply_external_knowledge = knowledge.apply_external_knowledge
_augment = pipeline.augment
reduce_all = reduction.reduce_all
get_llm_provider = llm_provider.get_llm_provider
Correlator = rules.Correlator
DEFAULT_RULES = rules.DEFAULT_RULES
mine_gap_candidates = rule_gap_miner.mine_gap_candidates
normalize_graph_state = graph_state.normalize_graph_state
try:  # Optional: message classes for tool planning/integration
    from langchain_core.messages import AIMessage, ToolMessage  # type: ignore
except Exception:  # pragma: no cover
    AIMessage = ToolMessage = None  # type: ignore

# Import batch processing helpers from scaffold (avoid circular import)
# These will be imported locally in functions that need them
    # Fallback if scaffold not available
    def _batch_extract_finding_fields(findings):
        try:
            import graph_nodes_scaffold
            return graph_nodes_scaffold._batch_extract_finding_fields(findings)
        except (ImportError, AttributeError):
            return {'severities': []}

    def _batch_filter_findings_by_severity(fields, severity_levels):
        try:
            import graph_nodes_scaffold
            return graph_nodes_scaffold._batch_filter_findings_by_severity(fields, severity_levels)
        except (ImportError, AttributeError):
            return []

    def _batch_check_baseline_status(findings):
        try:
            import graph_nodes_scaffold
            return graph_nodes_scaffold._batch_check_baseline_status(findings)
        except (ImportError, AttributeError):
            return []


def _append_warning(state: GraphState, module: str, stage: str, error: str, hint: str | None = None):
    wl = state.setdefault('warnings', [])
    wl.append({
        'module': module,
        'stage': stage,
        'error': error,
        'hint': hint
    })


def _findings_from_graph(state: GraphState) -> List[Finding]:
    out: List[Finding] = []
    for finding_dict in state.get('raw_findings', []) or []:
        try:
            # Provide minimal required fields; defaults for missing
            out.append(Finding(
                id=finding_dict.get('id','unknown'),
                title=finding_dict.get('title','(no title)'),
                severity=finding_dict.get('severity','info'),
                risk_score=int(finding_dict.get('risk_score', finding_dict.get('risk_total', 0)) or 0),
                metadata=finding_dict.get('metadata', {})
            ))
        except Exception:  # pragma: no cover - defensive
            continue
    return out


def enrich_findings(state: GraphState) -> GraphState:
    """Knowledge + augmentation stage.

    Converts raw_findings into enriched_findings using existing augment + knowledge code.
    """
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    try:
        findings = _findings_from_graph(state)
        sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = Report(meta=Meta(), summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
                        results=[sr], collection_warnings=[], scanner_errors=[], summary_extension=SummaryExtension(total_risk_score=0))
        astate = AgentState(report=report)
        astate = _augment(astate)
        astate = apply_external_knowledge(astate)
        # Export back to dict form
        enriched = []
        if astate.report and astate.report.results:
            for result in astate.report.results:
                for finding in result.findings:
                    enriched.append(finding.model_dump())
        state['enriched_findings'] = enriched
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'enrich', str(e))
        state.setdefault('enriched_findings', state.get('raw_findings', []))
    return state


def correlate_findings(state: GraphState) -> GraphState:
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    try:
        findings: List[Finding] = []
        for finding_dict in state.get('enriched_findings', []) or []:
            try:
                findings.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
            except Exception:
                continue
        sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
        report = Report(meta=Meta(), summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
                        results=[sr], collection_warnings=[], scanner_errors=[], summary_extension=SummaryExtension(total_risk_score=0))
        astate = AgentState(report=report)
        correlator = Correlator(DEFAULT_RULES)
        astate.correlations = correlator.apply(findings)
        for c in astate.correlations:
            for finding in findings:
                if finding.id in c.related_finding_ids and c.id not in finding.correlation_refs:
                    finding.correlation_refs.append(c.id)
        state['correlated_findings'] = [finding.model_dump() for finding in findings]
        state['correlations'] = [c.model_dump() for c in astate.correlations]
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'correlate', str(e))
        if 'correlated_findings' not in state:
            state['correlated_findings'] = state.get('enriched_findings', [])
    return state


def summarize_host_state(state: GraphState) -> GraphState:
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    try:
        # Iteration guard: default max iterations 3
        max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
        iters = int(state.get('iteration_count', 0))
        if iters >= max_iter:
            state['warnings'] = state.get('warnings', []) + [{'module': 'graph', 'stage': 'summarize', 'error': 'iteration_limit_reached'}]
            return state
        provider = get_llm_provider()
        findings_dicts = state.get('correlated_findings') or state.get('enriched_findings') or []
        findings: List[Finding] = []
        for finding_dict in findings_dicts:
            try:
                findings.append(Finding(**{k: v for k, v in finding_dict.items() if k in Finding.model_fields}))
            except Exception:
                continue
        reductions = reduce_all(findings)
        from models import Correlation as _C
        corr_objs = []
        for c in state.get('correlations', []) or []:
            try:
                corr_objs.append(_C(**c))
            except Exception:
                continue
        baseline_context = state.get('baseline_results') or {}
        summaries, _ = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)
        state['summary'] = summaries.model_dump()
        state['iteration_count'] = iters + 1
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'summarize', str(e))
    return state


def suggest_rules(state: GraphState) -> GraphState:
    """Mine candidate rules from enriched findings.

    Uses existing gap miner; writes a temp file to leverage current API.
    """
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    try:
        findings = state.get('enriched_findings') or []
        with tempfile.TemporaryDirectory() as td:
            p = tempfile.NamedTemporaryFile('w', delete=False, suffix='.json', dir=td)
            try:
                json.dump({'enriched_findings': findings}, p)
                p.flush(); p.close()
                from pathlib import Path
                res = mine_gap_candidates([Path(p.name)], risk_threshold=10, min_support=2)
            finally:
                try:
                    p.close()
                except Exception:
                    pass
        state['suggested_rules'] = res.get('suggestions', [])
    except Exception as e:  # pragma: no cover
        _append_warning(state, 'graph', 'rule_mine', str(e))
    return state


def should_suggest_rules(state: GraphState) -> str:  # Router for conditional edge
    """Decide whether to invoke rule suggestion based on enriched findings with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    Heuristic: If at least one enriched finding has severity == 'high' (case-insensitive),
    proceed to the expensive suggestion phase; otherwise end the graph.
    """
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    try:
        enriched = state.get('enriched_findings') or []
        if not enriched:
            try:  # pragma: no cover - trivial import guard
                from langgraph.graph import END  # type: ignore
                return END  # type: ignore
            except Exception:
                return "__end__"  # Fallback symbolic end if library missing

        # Batch check for high severity findings
        fields = _batch_extract_finding_fields(enriched)
        high_severity_indices = _batch_filter_findings_by_severity(fields, {'high'})

        if high_severity_indices:
            return "suggest_rules"

        # Import END lazily to avoid hard dependency at import time
        try:  # pragma: no cover - trivial import guard
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return "__end__"  # Fallback symbolic end if library missing
    except Exception:  # pragma: no cover - defensive
        try:
            from langgraph.graph import END  # type: ignore
            return END  # type: ignore
        except Exception:
            return "__end__"


def choose_post_summarize(state: GraphState) -> str:  # Router after summarize
    """Decide next step after summarize with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    Order of precedence:
    1. If baseline cycle not yet done and any enriched finding missing baseline_status -> plan_baseline
    2. Else defer to should_suggest_rules routing (suggest_rules or END)
    """
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    if not state.get('baseline_cycle_done'):
        enriched = state.get('enriched_findings') or []
        if not enriched:
            return should_suggest_rules(state)

        # Batch check for missing baseline status
        missing_indices = _batch_check_baseline_status(enriched)
        if missing_indices:
            return 'plan_baseline'

    # Delegate to existing router
    return should_suggest_rules(state)


def plan_baseline_queries(state: GraphState) -> GraphState:
    """Construct tool call messages for baseline queries if needed with optimized batch processing.

    Optimized: Uses batch processing to eliminate redundant finding iterations.
    Populates state['messages'] with an AIMessage containing tool_calls for each
    finding lacking baseline_status. ToolNode will execute these in batch.
    """
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    if AIMessage is None:  # Dependency missing; skip planning
        return state
    enriched = state.get('enriched_findings') or []
    if not enriched:
        return state

    # Batch check baseline status
    missing_indices = _batch_check_baseline_status(enriched)
    if not missing_indices:
        return state

    # Batch extract fields for missing findings
    missing_findings = [enriched[i] for i in missing_indices]
    fields = _batch_extract_finding_fields(missing_findings)

    # Build tool calls using batched data
    tool_calls = []
    host_id = __import__('os').environ.get('AGENT_GRAPH_HOST_ID','graph_host')

    for i, (fid, title, severity, scanner) in enumerate(zip(
        fields['ids'], fields['titles'], fields['severities'], fields['metadata_list']
    )):
        # Extract scanner from metadata if available
        scanner_name = 'mixed'
        if isinstance(scanner, dict):
            scanner_name = scanner.get('scanner', 'mixed')

        tool_calls.append({
            'name': 'query_baseline',
            'args': {
                'finding_id': fid or f'unknown_{i}',
                'title': title or '',
                'severity': severity or '',
                'scanner': scanner_name,
                'host_id': host_id
            }
        })

    msgs = state.get('messages') or []
    msgs.append(AIMessage(content="Baseline context required", tool_calls=tool_calls))  # type: ignore[arg-type]
    state['messages'] = msgs
    return state


def integrate_baseline_results(state: GraphState) -> GraphState:
    """Collect tool execution outputs into baseline_results mapping in state.

    Marks baseline_cycle_done to prevent repeated looping.
    """
    # Normalize state to ensure all mandatory keys exist
    state = normalize_graph_state(dict(state))  # type: ignore

    if ToolMessage is None:  # Dependency missing
        state['baseline_cycle_done'] = True
        return state
    msgs = state.get('messages') or []
    results = state.get('baseline_results') or {}
    for m in msgs:
        try:
            if isinstance(m, ToolMessage):
                # ToolMessage variants may expose .tool_call_id / .content; we expect dict content
                data_obj = getattr(m, 'content', None)
                if isinstance(data_obj, dict):
                    fid = data_obj.get('finding_id')
                    if isinstance(fid, str):
                        results[fid] = data_obj  # type: ignore[index]
        except Exception:  # pragma: no cover
            continue
    state['baseline_results'] = results
    state['baseline_cycle_done'] = True
    return state


__all__ = [
    'enrich_findings',
    'correlate_findings',
    'summarize_host_state',
    'suggest_rules',
    'should_suggest_rules',
    'choose_post_summarize',
    'plan_baseline_queries',
    'integrate_baseline_results'
]
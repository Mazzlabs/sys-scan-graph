from __future__ import annotations
"""Graph state schema (INT-FUT-GRAPH-STATE)

Central TypedDict describing the evolving state passed between LangGraph nodes
for the future LLM-driven analysis agent. This is a lightweight, JSON-friendly
structure distinct from the richer Pydantic models in models.py to allow
incremental population and external serialization without validation overhead.
"""
from typing import TypedDict, List, Dict, Any, Optional, Callable
import os
import logging


class GraphState(TypedDict, total=False):
    raw_findings: List[Dict[str, Any]]            # Raw scanner findings (pre-enrichment)
    enriched_findings: List[Dict[str, Any]]       # Findings after augmentation / risk recompute
    correlated_findings: List[Dict[str, Any]]     # Findings annotated with correlation references
    suggested_rules: List[Dict[str, Any]]         # Candidate correlation / refinement suggestions
    summary: Dict[str, Any]                       # LLM or heuristic summary artifacts
    warnings: List[Any]                           # Structured warning / error entries
    correlations: List[Dict[str, Any]]            # Correlation objects (optional)
    messages: List[Any]                           # LangChain message list for tool execution
    baseline_results: Dict[str, Any]              # Mapping finding_id -> baseline tool result
    baseline_cycle_done: bool                     # Guard to prevent infinite loop
    iteration_count: int                          # Number of summarize iterations executed
    metrics: Dict[str, Any]                       # Metrics for node durations / counters
    cache_keys: List[str]                         # Cache keys used during processing
    enrich_cache: Dict[str, List[Dict[str, Any]]]  # Mapping cache_key -> enriched findings list
    streaming_enabled: bool                        # Flag to enable streaming summarization
    human_feedback_pending: bool                   # Indicates waiting for human input / approval
    pending_tool_calls: List[Dict[str, Any]]       # Planned tool calls (pre ToolNode execution)
    risk_assessment: Dict[str, Any]                # Aggregated risk metrics / qualitative judgment
    compliance_check: Dict[str, Any]               # Compliance standards evaluation results
    errors: List[Dict[str, Any]]                   # Collected error records (optional, separate from warnings)
    degraded_mode: bool                            # Indicates system is in degraded / fallback mode
    human_feedback_processed: bool                 # Human feedback step completed
    final_metrics: Dict[str, Any]                  # Aggregated final metrics snapshot
    cache: Dict[str, Any]                          # General-purpose cache store (centralized)
    llm_provider_mode: str                         # Active LLM provider mode (normal|fallback|null)
    # Performance optimization fields
    current_stage: str                             # Current processing stage for observability
    start_time: str                                # Processing start timestamp
    cache_hits: List[str]                          # Cache hit tracking
    summarize_progress: float                      # Summarization progress (0.0-1.0)
    host_id: str                                   # Host identifier for baseline queries

# Runtime graph assembly (enhanced workflow builder)
try:  # Optional dependency guard
    from langgraph.graph import StateGraph, END  # type: ignore
    from langgraph.prebuilt import ToolNode  # type: ignore
    # Import legacy baseline nodes for fallback
    from .legacy.graph_nodes import summarize_host_state as legacy_summarize_host_state  # type: ignore
    from .legacy.graph_nodes import should_suggest_rules as legacy_should_suggest_rules  # type: ignore
    from .legacy.graph_nodes import choose_post_summarize as legacy_choose_post_summarize  # type: ignore
    from .legacy.graph_nodes import plan_baseline_queries as legacy_plan_baseline_queries  # type: ignore
    from .legacy.graph_nodes import integrate_baseline_results as legacy_integrate_baseline_results  # type: ignore
    from .legacy.graph_nodes import suggest_rules as legacy_suggest_rules  # type: ignore
    try:  # correlate may not exist legacy
        from .legacy.graph_nodes import correlate_findings as legacy_correlate_findings  # type: ignore
    except Exception:  # pragma: no cover
        legacy_correlate_findings = None  # type: ignore

    # Attempt to import enhanced scaffold nodes (all optional)
    try:
        from .graph_nodes_scaffold import (
            enrich_findings as scaffold_enrich_findings,
            enhanced_enrich_findings,
            summarize_host_state as scaffold_summarize_host_state,
            enhanced_summarize_host_state,
            suggest_rules as scaffold_suggest_rules,
            enhanced_suggest_rules,
            correlate_findings as scaffold_correlate_findings,
            plan_baseline_queries as scaffold_plan_baseline_queries,
            integrate_baseline_results as scaffold_integrate_baseline_results,
            tool_coordinator as scaffold_tool_coordinator,
            advanced_router as scaffold_advanced_router,
            should_suggest_rules as scaffold_should_suggest_rules,
            choose_post_summarize as scaffold_choose_post_summarize,
            risk_analyzer as scaffold_risk_analyzer,
            compliance_checker as scaffold_compliance_checker,
            error_handler as scaffold_error_handler,
            human_feedback_node as scaffold_human_feedback_node,
            cache_manager as scaffold_cache_manager,
            metrics_collector as scaffold_metrics_collector,
        )  # type: ignore
    except Exception:  # pragma: no cover - treat all as missing
        scaffold_enrich_findings = None  # type: ignore
        enhanced_enrich_findings = None  # type: ignore
        scaffold_summarize_host_state = None  # type: ignore
        enhanced_summarize_host_state = None  # type: ignore
        scaffold_suggest_rules = None  # type: ignore
        enhanced_suggest_rules = None  # type: ignore
        scaffold_correlate_findings = None  # type: ignore
        scaffold_plan_baseline_queries = None  # type: ignore
        scaffold_integrate_baseline_results = None  # type: ignore
        scaffold_tool_coordinator = None  # type: ignore
        scaffold_advanced_router = None  # type: ignore
        scaffold_should_suggest_rules = None  # type: ignore
        scaffold_choose_post_summarize = None  # type: ignore
        scaffold_risk_analyzer = None  # type: ignore
        scaffold_compliance_checker = None  # type: ignore
        scaffold_error_handler = None  # type: ignore
        scaffold_human_feedback_node = None  # type: ignore
        scaffold_cache_manager = None  # type: ignore
        scaffold_metrics_collector = None  # type: ignore

    # Attempt to import performance-optimized nodes
    try:
        from .legacy.graph_nodes_performance import (
            enrich_findings_batch,
            correlate_findings_batch,
            summarize_host_state_streaming,
            query_baseline_batch,
            parallel_node_execution,
        )  # type: ignore
    except Exception:  # pragma: no cover - performance nodes optional
        enrich_findings_batch = None  # type: ignore
        correlate_findings_batch = None  # type: ignore
        summarize_host_state_streaming = None  # type: ignore
        query_baseline_batch = None  # type: ignore
        parallel_node_execution = None  # type: ignore

    # Attempt to import scalability nodes
    try:
        from .legacy.graph_nodes_scalability import (
            parallel_findings_processing,
            horizontal_scaling_router,
            adaptive_batch_sizing,
            initialize_scalability,
            shutdown_scalability,
        )  # type: ignore
    except Exception:  # pragma: no cover - scalability nodes optional
        parallel_findings_processing = None  # type: ignore
        horizontal_scaling_router = None  # type: ignore
        adaptive_batch_sizing = None  # type: ignore
        initialize_scalability = None  # type: ignore
        shutdown_scalability = None  # type: ignore

    # Attempt to import reliability nodes
    try:
        from .legacy.graph_nodes_reliability import (
            reliable_enrich_findings,
            reliable_correlate_findings,
            reliable_summarize_state,
            initialize_reliability,
            shutdown_reliability,
        )  # type: ignore
    except Exception:  # pragma: no cover - reliability nodes optional
        reliable_enrich_findings = None  # type: ignore
        reliable_correlate_findings = None  # type: ignore
        reliable_summarize_state = None  # type: ignore
        initialize_reliability = None  # type: ignore
        shutdown_reliability = None  # type: ignore

    from .tools import query_baseline
except Exception:  # pragma: no cover - graph optional
    StateGraph = None  # type: ignore
    END = None  # type: ignore
    ToolNode = None  # type: ignore
    # Mark all imported references as None
    scaffold_enrich_findings = enhanced_enrich_findings = None  # type: ignore
    scaffold_summarize_host_state = enhanced_summarize_host_state = None  # type: ignore
    scaffold_suggest_rules = enhanced_suggest_rules = None  # type: ignore
    scaffold_correlate_findings = None  # type: ignore
    legacy_correlate_findings = None  # type: ignore
    scaffold_plan_baseline_queries = legacy_plan_baseline_queries = None  # type: ignore
    scaffold_integrate_baseline_results = legacy_integrate_baseline_results = None  # type: ignore
    scaffold_tool_coordinator = None  # type: ignore
    scaffold_advanced_router = None  # type: ignore
    scaffold_should_suggest_rules = legacy_should_suggest_rules = None  # type: ignore
    scaffold_choose_post_summarize = legacy_choose_post_summarize = None  # type: ignore
    scaffold_risk_analyzer = scaffold_compliance_checker = None  # type: ignore
    scaffold_error_handler = scaffold_human_feedback_node = None  # type: ignore
    scaffold_cache_manager = scaffold_metrics_collector = None  # type: ignore
    # Performance nodes
    enrich_findings_batch = correlate_findings_batch = None  # type: ignore
    summarize_host_state_streaming = query_baseline_batch = None  # type: ignore
    parallel_node_execution = None  # type: ignore
    # Scalability nodes
    parallel_findings_processing = horizontal_scaling_router = None  # type: ignore
    adaptive_batch_sizing = initialize_scalability = None  # type: ignore
    shutdown_scalability = None  # type: ignore
    # Reliability nodes
    reliable_enrich_findings = reliable_correlate_findings = None  # type: ignore
    reliable_summarize_state = initialize_reliability = None  # type: ignore
    shutdown_reliability = None  # type: ignore
    query_baseline = None  # type: ignore


    pass

def _select(
    *candidates: Optional[Callable],
) -> Optional[Callable]:
    """Return first callable synchronous candidate or None. Skips async functions for sync API compatibility."""
    import inspect
    
    # Only return synchronous functions to ensure compatibility with LangGraph sync API
    for c in candidates:
        if callable(c) and not inspect.iscoroutinefunction(c):
            return c  # type: ignore
    
    # Don't return async functions as they cause "No synchronous function provided" errors
    return None


def build_workflow(enhanced: Optional[bool] = None):  # type: ignore
    """Build and compile a StateGraph workflow.

    Parameters:
        enhanced: If True, prefer enhanced scaffold async nodes. If False, use baseline/legacy.
                  If None, derive from env AGENT_GRAPH_MODE ("enhanced" => True).
                  Defaults to False if enhanced nodes are not available.
    Returns:
        (workflow, app) tuple – uncompiled workflow object and compiled app (or (None, None)).
    """
    if StateGraph is None:
        return None, None
    if enhanced is None:
        mode = os.getenv("AGENT_GRAPH_MODE", "baseline").lower()  # Default to baseline
        enhanced = mode == "enhanced"

    # Attempt dynamic import recovery if prior import during module init failed
    global scaffold_enrich_findings, enhanced_enrich_findings, scaffold_summarize_host_state, enhanced_summarize_host_state
    global scaffold_suggest_rules, enhanced_suggest_rules, scaffold_correlate_findings
    global scaffold_risk_analyzer, scaffold_compliance_checker, scaffold_error_handler, scaffold_human_feedback_node
    global scaffold_cache_manager, scaffold_metrics_collector
    global enrich_findings_batch, correlate_findings_batch, summarize_host_state_streaming, query_baseline_batch, parallel_node_execution
    global parallel_findings_processing, horizontal_scaling_router, adaptive_batch_sizing, initialize_scalability, shutdown_scalability
    global reliable_enrich_findings, reliable_correlate_findings, reliable_summarize_state, initialize_reliability, shutdown_reliability
    if scaffold_enrich_findings is None:
        try:  # pragma: no cover - recovery path
            from importlib import import_module
            sm = import_module('agent.graph_nodes_scaffold')
            scaffold_enrich_findings = getattr(sm, 'enrich_findings', None)
            enhanced_enrich_findings = getattr(sm, 'enhanced_enrich_findings', None)
            scaffold_summarize_host_state = getattr(sm, 'summarize_host_state', None)
            enhanced_summarize_host_state = getattr(sm, 'enhanced_summarize_host_state', None)
            scaffold_suggest_rules = getattr(sm, 'suggest_rules', None)
            enhanced_suggest_rules = getattr(sm, 'enhanced_suggest_rules', None)
            scaffold_correlate_findings = getattr(sm, 'correlate_findings', None)
            scaffold_risk_analyzer = getattr(sm, 'risk_analyzer', None)
            scaffold_compliance_checker = getattr(sm, 'compliance_checker', None)
            scaffold_error_handler = getattr(sm, 'error_handler', None)
            scaffold_human_feedback_node = getattr(sm, 'human_feedback_node', None)
            scaffold_cache_manager = getattr(sm, 'cache_manager', None)
            scaffold_metrics_collector = getattr(sm, 'metrics_collector', None)

            # Import performance nodes
            pm = import_module('agent.legacy.graph_nodes_performance')
            enrich_findings_batch = getattr(pm, 'enrich_findings_batch', None)
            correlate_findings_batch = getattr(pm, 'correlate_findings_batch', None)
            summarize_host_state_streaming = getattr(pm, 'summarize_host_state_streaming', None)
            query_baseline_batch = getattr(pm, 'query_baseline_batch', None)
            parallel_node_execution = getattr(pm, 'parallel_node_execution', None)

            # Import scalability nodes
            sm = import_module('agent.legacy.graph_nodes_scalability')
            parallel_findings_processing = getattr(sm, 'parallel_findings_processing', None)
            horizontal_scaling_router = getattr(sm, 'horizontal_scaling_router', None)
            adaptive_batch_sizing = getattr(sm, 'adaptive_batch_sizing', None)
            initialize_scalability = getattr(sm, 'initialize_scalability', None)
            shutdown_scalability = getattr(sm, 'shutdown_scalability', None)

            # Import reliability nodes
            rm = import_module('agent.legacy.graph_nodes_reliability')
            reliable_enrich_findings = getattr(rm, 'reliable_enrich_findings', None)
            reliable_correlate_findings = getattr(rm, 'reliable_correlate_findings', None)
            reliable_summarize_state = getattr(rm, 'reliable_summarize_state', None)
            initialize_reliability = getattr(rm, 'initialize_reliability', None)
            shutdown_reliability = getattr(rm, 'shutdown_reliability', None)
        except Exception:
            # If enhanced imports fail, force baseline mode
            enhanced = False
            pass

    # If enhanced mode was requested but scaffold functions are not available, fall back to baseline
    if enhanced and scaffold_enrich_findings is None:
        enhanced = False

    # Core selection - prefer reliability, then performance, then enhanced, then scaffold, then legacy
    enrich_node = _select(reliable_enrich_findings, enrich_findings_batch, scaffold_enrich_findings, enhanced_enrich_findings)
    if enrich_node is None:
        logger = logging.getLogger(__name__)
        logger.warning("build_workflow: No enrich node available - workflow assembly failed")
        if enhanced:
            logger.error("AGENT_GRAPH_MODE=enhanced but required enhancements are missing")
            raise RuntimeError("Enhanced workflow mode requires scaffold nodes but none are available. "
                             "Ensure graph_nodes_scaffold.py is properly implemented or set AGENT_GRAPH_MODE=baseline")
        return None, None

    summarize_node = _select(reliable_summarize_state, summarize_host_state_streaming, enhanced_summarize_host_state, scaffold_summarize_host_state, legacy_summarize_host_state)
    correlate_node = _select(reliable_correlate_findings, correlate_findings_batch, scaffold_correlate_findings, legacy_correlate_findings)
    suggest_node = _select(enhanced_suggest_rules, scaffold_suggest_rules, legacy_suggest_rules)
    plan_baseline_node = _select(query_baseline_batch, scaffold_plan_baseline_queries, legacy_plan_baseline_queries)
    integrate_baseline_node = _select(scaffold_integrate_baseline_results, legacy_integrate_baseline_results)
    choose_post_summarize_node = _select(scaffold_choose_post_summarize, legacy_choose_post_summarize)
    should_suggest_rules_node = _select(scaffold_should_suggest_rules, legacy_should_suggest_rules)
    advanced_router_node = _select(scaffold_advanced_router)
    tool_coord_node = _select(scaffold_tool_coordinator)
    risk_node = _select(scaffold_risk_analyzer)
    compliance_node = _select(scaffold_compliance_checker)
    error_handler_node = _select(scaffold_error_handler)
    human_feedback_node = _select(scaffold_human_feedback_node)
    cache_manager_node = _select(scaffold_cache_manager)
    metrics_collector_node = _select(scaffold_metrics_collector)
    # Scalability nodes
    parallel_processing_node = _select(parallel_findings_processing)
    scaling_router_node = _select(horizontal_scaling_router)

    wf = StateGraph(GraphState)  # type: ignore[arg-type]
    # Node registration
    wf.add_node("enrich", enrich_node)  # type: ignore[arg-type]
    if correlate_node:
        wf.add_node("correlate", correlate_node)  # type: ignore[arg-type]
    if risk_node:
        wf.add_node("risk", risk_node)  # type: ignore[arg-type]
    if compliance_node:
        wf.add_node("compliance", compliance_node)  # type: ignore[arg-type]
    wf.add_node("summarize", summarize_node)  # type: ignore[arg-type]
    if plan_baseline_node:
        wf.add_node("plan_baseline", plan_baseline_node)  # type: ignore[arg-type]
    if ToolNode is not None and query_baseline is not None:
        wf.add_node("baseline_tools", ToolNode([query_baseline]))  # type: ignore[arg-type]
    if integrate_baseline_node:
        wf.add_node("integrate_baseline", integrate_baseline_node)  # type: ignore[arg-type]
    wf.add_node("suggest_rules", suggest_node)  # type: ignore[arg-type]
    if error_handler_node:
        wf.add_node("error_handler", error_handler_node)  # type: ignore[arg-type]
    if human_feedback_node:
        wf.add_node("human_feedback", human_feedback_node)  # type: ignore[arg-type]
    if cache_manager_node:
        wf.add_node("cache_manager", cache_manager_node)  # type: ignore[arg-type]
    if metrics_collector_node:
        wf.add_node("metrics_collector", metrics_collector_node)  # type: ignore[arg-type]
    # Scalability nodes
    if parallel_processing_node:
        wf.add_node("parallel_processing", parallel_processing_node)  # type: ignore[arg-type]
    if scaling_router_node:
        wf.add_node("scaling_router", scaling_router_node)  # type: ignore[arg-type]

    # Entry
    wf.set_entry_point("enrich")
    # Linear progression with optional nodes
    if correlate_node:
        wf.add_edge("enrich", "correlate")
        prev = "correlate"
    else:
        prev = "enrich"
    if risk_node:
        wf.add_edge(prev, "risk")
        prev = "risk"
    if compliance_node:
        wf.add_edge(prev, "compliance")
        prev = "compliance"
    wf.add_edge(prev, "summarize")

    # Post summarize conditional: baseline planning or proceed
    def _post_summarize_router(state: GraphState) -> str:  # type: ignore
        # Check if scalability routing is available and needed
        if callable(scaling_router_node):  # type: ignore
            scaling_decision = scaling_router_node(state)  # type: ignore
            if scaling_decision in ["parallel_processing", "batch_processing"]:
                return scaling_decision

        # If baseline cycle logic present, delegate to choose_post_summarize; else always proceed
        if callable(choose_post_summarize_node):  # type: ignore
            return choose_post_summarize_node(state)  # type: ignore
        return "proceed_suggest"

    mapping_after_summarize = {"proceed_suggest": "suggest_rules", "suggest_rules": "suggest_rules"}
    if plan_baseline_node:
        mapping_after_summarize["plan_baseline"] = "plan_baseline"
    # Add scalability mappings
    if parallel_processing_node:
        mapping_after_summarize["parallel_processing"] = "parallel_processing"
    if END is not None:
        if metrics_collector_node is not None:
            mapping_after_summarize[END] = "metrics_collector"  # type: ignore
        else:
            mapping_after_summarize[END] = END  # type: ignore
    wf.add_conditional_edges("summarize", _post_summarize_router, mapping_after_summarize)  # type: ignore[arg-type]

    # Baseline cycle
    if plan_baseline_node and integrate_baseline_node and ToolNode is not None and query_baseline is not None:
        wf.add_edge("plan_baseline", "baseline_tools")
        wf.add_edge("baseline_tools", "integrate_baseline")
        wf.add_edge("integrate_baseline", "summarize")
        try:  # optional shortcut
            wf.add_edge("baseline_tools", "summarize")
        except Exception:  # pragma: no cover
            pass

    # Add scalability edges
    if parallel_processing_node:
        wf.add_edge("parallel_processing", "suggest_rules")

    # advanced_router currently disabled in workflow wiring pending refactor (would require router-only integration)

    # Operational tail chain
    tail_prev = "suggest_rules"
    for tail in ["error_handler", "human_feedback", "cache_manager", "metrics_collector"]:
        if tail in wf.nodes:  # type: ignore
            wf.add_edge(tail_prev, tail)
            tail_prev = tail
    if END is not None:
        wf.add_edge(tail_prev, END)  # type: ignore[arg-type]

    try:
        compiled = wf.compile()
    except Exception:  # pragma: no cover
        compiled = None
    return wf, compiled


# Build default workflow at import using env toggle
workflow, app = build_workflow()

__all__ = ["GraphState", "workflow", "app", "build_workflow"]
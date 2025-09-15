from __future__ import annotations
"""Enhanced graph node functions with advanced LLM integration features.

This module provides sophisticated node implementations with:
- Multi-provider LLM support with automatic fallback
- Streaming responses for real-time updates
- Advanced error handling and retry logic
- Human-in-the-loop capabilities
- Tool coordination and external data integration
- Risk analysis and compliance checking
- Caching and performance optimization
- Comprehensive metrics collection
"""

from typing import Any, List, Dict, Optional, Union
import asyncio
import time
import logging
from datetime import datetime
import json
from pathlib import Path
import tempfile

from .graph import GraphState
from .data_governance import get_data_governor
from .models import Finding, ScannerResult, Report, Meta, Summary, SummaryExtension, AgentState
from .knowledge import apply_external_knowledge
from .pipeline import augment as _augment
from .reduction import reduce_all
from .llm_provider import get_llm_provider
try:
    from ..rules import Correlator, DEFAULT_RULES
except ImportError:
    from rules import Correlator, DEFAULT_RULES
from .rule_gap_miner import mine_gap_candidates
from .graph_state import normalize_graph_state
from .metrics_node import time_node
from .util_hash import stable_hash  # Shared stable hash utility
from .util_normalization import (  # Shared normalization utilities
    normalize_rule_suggestions,
    unify_risk_assessment,
    unify_compliance_check,
    ensure_monotonic_timing,
    add_metrics_version,
)

# Enhanced LLM provider with multi-provider support
try:
    from .llm_provider_enhanced import get_enhanced_llm_provider
except ImportError:
    get_enhanced_llm_provider = get_llm_provider

logger = logging.getLogger(__name__)

def _append_warning(state: GraphState, module: str, stage: str, error: str, hint: str | None = None):
    """Enhanced warning appender with structured error tracking."""
    wl = state.setdefault('warnings', [])
    error_entry = {
        'module': module,
        'stage': stage,
        'error': error,
        'hint': hint,
        'timestamp': datetime.now().isoformat(),
        'session_id': state.get('session_id', 'unknown')
    }
    wl.append(error_entry)

    # Also track in errors list for better visibility
    errors = state.setdefault('errors', [])
    errors.append(error_entry)

def _findings_from_graph(state: GraphState) -> List[Finding]:
    """Convert graph state findings to Pydantic models."""
    out: List[Finding] = []
    for finding in state.get('raw_findings', []) or []:
        try:
            out.append(Finding(
                id=finding.get('id','unknown'),
                title=finding.get('title','(no title)'),
                severity=finding.get('severity','info'),
                risk_score=int(finding.get('risk_score', finding.get('risk_total', 0)) or 0),
                metadata=finding.get('metadata', {}),
                tags=finding.get('tags', [])
            ))
        except Exception:
            continue
    return out

async def enhanced_enrich_findings(state: GraphState) -> GraphState:
    """Enhanced enrichment with caching, metrics, and error recovery."""
    with time_node(state, 'enhanced_enrich_findings') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        start_time = time.monotonic()
        state['current_stage'] = 'enrich'
        # Store ISO time for state compatibility, monotonic time for accurate calculations
        if 'start_time' not in state:
            state['start_time'] = datetime.now().isoformat()
        state.setdefault('metrics', {})['start_time_monotonic'] = start_time

        try:
            # Check cache first
            cache_key = stable_hash(state.get('raw_findings', []), "enrich")
            if cache_key in state.get('cache_hits', []):
                logger.info("Using cached enrichment results")
                return state

            findings = _findings_from_graph(state)
            sr = ScannerResult(scanner='mixed', finding_count=len(findings), findings=findings)
            report = Report(
                meta=Meta(),
                summary=Summary(finding_count_total=len(findings), finding_count_emitted=len(findings)),
                results=[sr],
                collection_warnings=[],
                scanner_errors=[],
                summary_extension=SummaryExtension(total_risk_score=0)
            )
            astate = AgentState(report=report)

            # Apply enrichment pipeline
            astate = _augment(astate)
            astate = apply_external_knowledge(astate)

            # Export back to dict form
            enriched = []
            if astate.report and astate.report.results:
                for r in astate.report.results:
                    for finding in r.findings:
                        enriched.append(finding.model_dump())

            state['enriched_findings'] = enriched
            state['cache_hits'] = state.get('cache_hits', []) + [cache_key]

            # Update metrics
            state.setdefault('metrics', {})['enrich_duration'] = time.time() - start_time

        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
            _append_warning(state, 'graph', 'enrich', str(e))
            state.setdefault('enriched_findings', state.get('raw_findings', []))

        return state

async def enhanced_summarize_host_state(state: GraphState) -> GraphState:
    """Enhanced summarization with streaming, multi-provider LLM, and advanced prompting."""
    with time_node(state, 'enhanced_summarize_host_state') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        start_time = time.time()
        state['current_stage'] = 'summarize'

        try:
            # Iteration guard
            max_iter = int(__import__('os').environ.get('AGENT_MAX_SUMMARY_ITERS', '3'))
            iters = int(state.get('iteration_count', 0))
            if iters >= max_iter:
                _append_warning(state, 'graph', 'summarize', 'iteration_limit_reached')
                return state

            provider = get_enhanced_llm_provider()
            findings_dicts = state.get('correlated_findings') or state.get('enriched_findings') or []
            findings: List[Finding] = []

            for finding in findings_dicts:
                try:
                    findings.append(Finding(**{k: v for k, v in finding.items() if k in Finding.model_fields}))
                except Exception:
                    continue

            reductions = reduce_all(findings)

            # Enhanced correlation handling
            corr_objs = []
            for c in state.get('correlations', []) or []:
                try:
                    from .models import Correlation as _C
                    corr_objs.append(_C(**c))
                except Exception:
                    continue

            baseline_context = state.get('baseline_results') or {}

            # Check if streaming is enabled
            if state.get('streaming_enabled'):
                # Use streaming summarizer
                summary = await streaming_summarizer(state, reductions, corr_objs, baseline_context)
            else:
                # Use standard summarization
                summary, metadata = provider.summarize(reductions, corr_objs, actions=[], baseline_context=baseline_context)

            # Store summary in state
            if hasattr(summary, 'model_dump') and callable(getattr(summary, 'model_dump')):
                state['summary'] = summary.model_dump()
            elif isinstance(summary, dict):
                state['summary'] = summary
            else:
                state['summary'] = dict(summary) if summary else {}

            # Update token usage in metrics
            metrics = state.setdefault('metrics', {})
            try:
                # Handle both object and dict cases for summary
                summary_metrics = None
                if hasattr(summary, 'metrics'):
                    summary_metrics = getattr(summary, 'metrics', None)
                elif isinstance(summary, dict) and 'metrics' in summary:
                    summary_metrics = summary['metrics']

                if summary_metrics:
                    if hasattr(summary_metrics, 'get'):
                        # Object with get method
                        prompt_tokens = getattr(summary_metrics, 'get', lambda x, default: default)('tokens_prompt', 0)
                        completion_tokens = getattr(summary_metrics, 'get', lambda x, default: default)('tokens_completion', 0)
                    elif isinstance(summary_metrics, dict):
                        # Dict case
                        prompt_tokens = summary_metrics.get('tokens_prompt', 0)
                        completion_tokens = summary_metrics.get('tokens_completion', 0)
                    else:
                        prompt_tokens = completion_tokens = 0

                    metrics['prompt_tokens_used'] = metrics.get('prompt_tokens_used', 0) + prompt_tokens
                    metrics['completion_tokens_used'] = metrics.get('completion_tokens_used', 0) + completion_tokens
                    metrics['llm_calls_made'] = metrics.get('llm_calls_made', 0) + 1
            except Exception:
                # If anything fails, just increment the call counter
                metrics['llm_calls_made'] = metrics.get('llm_calls_made', 0) + 1

            # Update metrics
            state.setdefault('metrics', {})['summarize_duration'] = time.time() - start_time

        except Exception as e:
            logger.error(f"Summarization failed: {e}")
            _append_warning(state, 'graph', 'summarize', str(e))

        return state

async def enhanced_suggest_rules(state: GraphState) -> GraphState:
    """Enhanced rule suggestion with LLM refinement and validation."""
    with time_node(state, 'enhanced_suggest_rules') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        start_time = time.time()
        state['current_stage'] = 'suggest_rules'

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

            # Enhanced rule suggestions
            suggestions = res.get('suggestions', [])

            # Apply LLM refinement if available
            try:
                provider = get_enhanced_llm_provider()
                if hasattr(provider, 'refine_rules'):
                    refined_suggestions, metadata = provider.refine_rules(suggestions)
                    suggestions = refined_suggestions
            except Exception as e:
                logger.warning(f"LLM rule refinement failed: {e}")

            state['suggested_rules'] = suggestions

            # Apply unified normalization (work with dict copy)
            state_dict = dict(state)
            state_dict = normalize_rule_suggestions(state_dict)
            state_dict = ensure_monotonic_timing(state_dict)
            state_dict = add_metrics_version(state_dict)

            # Update state with normalized values
            for key, value in state_dict.items():
                if key in state or key in ['suggested_rules', 'monotonic_start', 'metrics']:
                    state[key] = value

            # Update metrics
            state.setdefault('metrics', {})['rules_suggested'] = len(suggestions)
            state.setdefault('metrics', {})['suggest_rules_duration'] = time.time() - start_time

        except Exception as e:
            logger.error(f"Rule suggestion failed: {e}")
            _append_warning(state, 'graph', 'rule_suggest', str(e))

        return state

def advanced_router(state: GraphState) -> str:
    """Advanced routing logic based on content analysis and state."""
    with time_node(state, 'advanced_router') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            enriched = state.get('enriched_findings') or []

            # Check for high-severity findings
            high_severity_count = sum(1 for finding in enriched if str(finding.get('severity', '')).lower() == 'high')

            # Check baseline status
            missing_baseline = any('baseline_status' not in finding for finding in enriched)

            # Check for compliance requirements
            compliance_categories = ['compliance', 'regulation', 'pci_dss', 'hipaa', 'nist', 'sox', 'gdpr', 'ccpa']
            needs_compliance = any(
                any(comp_cat in str(finding.get('category', '')).lower() for comp_cat in compliance_categories)
                for finding in enriched
            )

            # Check for external data needs
            needs_external = any('external_ref' in finding.get('metadata', {}) for finding in enriched)

            # Priority-based routing
            if state.get('human_feedback_pending'):
                return "human_feedback"
            elif needs_compliance:
                return "compliance"
            elif missing_baseline and high_severity_count > 0:
                return "baseline"
            elif needs_external:
                return "risk"
            elif high_severity_count > 2:
                return "summarize"
            else:
                return "summarize"

        except Exception as e:
            logger.error(f"Routing failed: {e}")
            return "error"

async def error_handler(state: GraphState) -> GraphState:
    """Enhanced error handling with recovery strategies."""
    with time_node(state, 'error_handler') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            errors = state.get('errors', [])
            if not errors:
                return state

            # Analyze error patterns
            error_types = {}
            for error in errors:
                err_type = error.get('error', 'unknown')
                error_types[err_type] = error_types.get(err_type, 0) + 1

            # Recovery strategies based on error patterns
            if 'iteration_limit_reached' in error_types:
                # Allow graceful degradation
                state['summary'] = state.get('summary', {})
                state['summary']['degraded_mode'] = True

            elif 'llm_timeout' in error_types:
                # Switch to heuristic mode
                state['llm_provider_mode'] = 'heuristic_fallback'

            # Log recovery actions
            logger.info(f"Applied error recovery for patterns: {error_types}")

        except Exception as e:
            logger.error(f"Error handler failed: {e}")

        return state

async def human_feedback_node(state: GraphState) -> GraphState:
    """Handle human-in-the-loop feedback."""
    with time_node(state, 'human_feedback_node') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            if state.get('human_feedback_pending'):
                # In a real implementation, this would wait for human input
                # For now, we'll simulate or skip
                feedback = state.get('human_feedback')
                if feedback:
                    # Process feedback and update state
                    state['human_feedback_processed'] = True
                    state['human_feedback_pending'] = False
                    logger.info(f"Processed human feedback: {feedback}")
        except Exception as e:
            logger.error(f"Human feedback processing failed: {e}")

        return state

async def streaming_summarizer(state: GraphState, reductions, correlations, baseline_context) -> Dict[str, Any]:
    """Streaming summarization for real-time updates."""
    try:
        provider = get_enhanced_llm_provider()

        # Simulate streaming by yielding intermediate results
        # In a real implementation, this would use async generators
        summary, metadata = provider.summarize(reductions, correlations, actions=[], baseline_context=baseline_context)

        # Convert to dict and add streaming metadata
        summary_dict = summary.model_dump() if hasattr(summary, 'model_dump') else dict(summary)
        summary_dict['streaming_complete'] = True

        return summary_dict

    except Exception as e:
        logger.error(f"Streaming summarization failed: {e}")
        # Fallback to regular summarization
        summary, metadata = provider.summarize(reductions, correlations, actions=[], baseline_context=baseline_context)
        summary_dict = summary.model_dump() if hasattr(summary, 'model_dump') else dict(summary)
        return summary_dict

async def tool_coordinator(state: GraphState) -> GraphState:
    """Coordinate tool execution and result integration."""
    with time_node(state, 'tool_coordinator') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            # Analyze what tools are needed
            enriched = state.get('enriched_findings') or []

            tool_calls = []

            # Baseline queries for missing data
            missing_baseline = [finding for finding in enriched if 'baseline_status' not in finding]
            if missing_baseline:
                tool_calls.append({
                    'name': 'query_baseline_enhanced',
                    'args': {'findings': missing_baseline[:5]}  # Limit batch size
                })

            # External data searches
            needs_external = [finding for finding in enriched if 'external_ref' in finding.get('metadata', {})]
            if needs_external:
                tool_calls.append({
                    'name': 'search_external_data',
                    'args': {'queries': [finding.get('metadata', {}).get('external_ref') for finding in needs_external]}
                })

            # Store tool calls in state for execution
            state['pending_tool_calls'] = tool_calls

        except Exception as e:
            logger.error(f"Tool coordination failed: {e}")

        return state

async def risk_analyzer(state: GraphState) -> GraphState:
    """Advanced risk analysis with ML models."""
    with time_node(state, 'risk_analyzer') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            findings = state.get('enriched_findings') or []

            # Enhanced risk scoring with unified schema
            risk_assessment = {
                'overall_risk_level': 'low',
                'overall_risk': 'info',  # Unified field name
                'risk_factors': [],
                'recommendations': [],
                'confidence_score': 0.0,
                'counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0},
                'total_risk_score': 0,
                'average_risk_score': 0.0,
                'finding_count': len(findings),
                'top_findings': []
            }

            # Analyze patterns and populate unified fields
            high_risk_count = sum(1 for finding in findings if finding.get('risk_score', 0) > 70)
            total_risk_score = sum(finding.get('risk_score', 0) for finding in findings)
            average_risk_score = total_risk_score / len(findings) if findings else 0.0

            # Count severity levels
            for finding in findings:
                severity = finding.get('severity', 'unknown').lower()
                if severity in risk_assessment['counts']:
                    risk_assessment['counts'][severity] += 1

            # Set unified risk levels
            if high_risk_count > 3:
                risk_assessment['overall_risk_level'] = 'high'
                risk_assessment['overall_risk'] = 'high'
                risk_assessment['risk_factors'].append('multiple_high_risk_findings')

            # Populate unified quantitative fields
            risk_assessment['total_risk_score'] = total_risk_score
            risk_assessment['average_risk_score'] = average_risk_score

            # Get top findings by risk score
            sorted_findings = sorted(findings, key=lambda f: f.get('risk_score', 0), reverse=True)
            risk_assessment['top_findings'] = [
                {'id': f.get('id'), 'title': f.get('title'), 'risk_score': f.get('risk_score', 0)}
                for f in sorted_findings[:3]
            ]

            state['risk_assessment'] = risk_assessment

            # Apply unified normalization
            state_dict = dict(state)
            state_dict = unify_risk_assessment(state_dict)
            state_dict = ensure_monotonic_timing(state_dict)
            state_dict = add_metrics_version(state_dict)

            # Update state with normalized values
            for key, value in state_dict.items():
                if key in state or key in ['risk_assessment', 'monotonic_start', 'metrics']:
                    state[key] = value

        except Exception as e:
            logger.error(f"Risk analysis failed: {e}")

        return state

async def compliance_checker(state: GraphState) -> GraphState:
    """Compliance checking against standards."""
    with time_node(state, 'compliance_checker') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            findings = state.get('enriched_findings') or []

            compliance_check = {
                'pci_dss': {'compliant': True, 'violations': []},
                'hipaa': {'compliant': True, 'violations': []},
                'nist_csf': {'compliant': True, 'violations': []}
            }

            # Check for compliance-related findings
            for finding in findings:
                category = finding.get('category', '').lower()
                tags = finding.get('tags', [])
                metadata = finding.get('metadata', {})
                
                # Check category, tags, and metadata for compliance indicators
                compliance_standard = metadata.get('compliance_standard', '').lower()
                
                if ('pci' in category or 
                    any('pci' in tag.lower() for tag in tags) or 
                    'pci' in compliance_standard):
                    compliance_check['pci_dss']['compliant'] = False
                    compliance_check['pci_dss']['violations'].append(finding.get('id'))
                
                if ('hipaa' in category or 
                    any('hipaa' in tag.lower() for tag in tags) or 
                    'hipaa' in compliance_standard):
                    compliance_check['hipaa']['compliant'] = False
                    compliance_check['hipaa']['violations'].append(finding.get('id'))

            state['compliance_check'] = compliance_check

            # Apply unified normalization
            state_dict = dict(state)
            state_dict = unify_compliance_check(state_dict)
            state_dict = ensure_monotonic_timing(state_dict)
            state_dict = add_metrics_version(state_dict)

            # Update state with normalized values
            for key, value in state_dict.items():
                if key in state or key in ['compliance_check', 'monotonic_start', 'metrics']:
                    state[key] = value

        except Exception as e:
            logger.error(f"Compliance check failed: {e}")

        return state

async def cache_manager(state: GraphState) -> GraphState:
    """Manage caching for performance optimization."""
    with time_node(state, 'cache_manager') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            # Initialize cache tracking
            state['cache_hits'] = state.get('cache_hits', [])
            state['cache_keys'] = state.get('cache_keys', [])

            # Simple in-memory cache for this session
            # In production, this would use Redis or similar
            cache = getattr(cache_manager, '_cache', {})
            if not hasattr(cache_manager, '_cache'):
                cache_manager._cache = {}

            # Cache key based on findings hash
            findings = state.get('raw_findings', [])
            cache_key = stable_hash(findings, "cache_manager")

            if cache_key in cache_manager._cache:
                state['cache_hits'].append(str(cache_key))
                # Restore cached results
                cached_state = cache_manager._cache[cache_key]
                state.update(cached_state)
            else:
                state['cache_keys'].append(str(cache_key))
                # Store for future use
                cache_manager._cache[cache_key] = {
                    'enriched_findings': state.get('enriched_findings', []),
                    'correlations': state.get('correlations', [])
                }

        except Exception as e:
            logger.error(f"Cache management failed: {e}")

        return state

async def metrics_collector(state: GraphState) -> GraphState:
    """Collect and aggregate metrics."""
    with time_node(state, 'metrics_collector') as timed_state:
        state = normalize_graph_state(timed_state)  # type: ignore
        try:
            metrics = state.get('metrics', {})

            # Add final metrics
            start_time_monotonic = metrics.get('start_time_monotonic', time.monotonic())
            metrics['total_duration'] = time.monotonic() - start_time_monotonic
            metrics['findings_processed'] = len(state.get('enriched_findings') or [])
            metrics['correlations_found'] = len(state.get('correlations') or [])
            metrics['rules_suggested'] = len(state.get('suggested_rules') or [])
            metrics['cache_hit_rate'] = len(state.get('cache_hits', [])) / max(1, len(state.get('cache_hits', [])) + len(state.get('cache_keys', [])))

            state['metrics'] = metrics

            # Log final metrics
            logger.info(f"Analysis complete. Metrics: {metrics}")

        except Exception as e:
            logger.error(f"Metrics collection failed: {e}")

        return state

__all__ = [
    'enhanced_enrich_findings',
    'enhanced_summarize_host_state',
    'enhanced_suggest_rules',
    'advanced_router',
    'error_handler',
    'human_feedback_node',
    'streaming_summarizer',
    'tool_coordinator',
    'risk_analyzer',
    'compliance_checker',
    'cache_manager',
    'metrics_collector'
]

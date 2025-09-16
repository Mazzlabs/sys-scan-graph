from __future__ import annotations

# Schema version for contract versioning
GRAPH_STATE_SCHEMA_VERSION = "1.0.0"
GRAPH_STATE_SCHEMA_LAST_UPDATED = "2025-01-09"

"""GraphState normalization and validation utilities.

This module provides a canonical GraphState schema and normalization utilities
to ensure deterministic behavior across all LangGraph nodes.
"""

from typing import Dict, List, Any, Optional, TypedDict, Union
from pydantic import BaseModel, Field
import time

# Import GraphState for type hints
try:
    from .graph import GraphState
except ImportError:
    # Fallback for circular import issues
    GraphState = Dict[str, Any]  # type: ignore


class GraphStateSchema(BaseModel):
    """Canonical Pydantic schema for GraphState validation and normalization.

    Version: 1.0.0
    Last Updated: 2025-01-09
    Changes:
    - v1.0.0: Initial unified schema with risk_assessment standardization
    """

    # Core findings data
    raw_findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    enriched_findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    correlated_findings: Optional[List[Dict[str, Any]]] = None
    suggested_rules: Optional[List[Dict[str, Any]]] = None

    # Analysis results
    summary: Optional[Dict[str, Any]] = None
    correlations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    # Operational state
    warnings: Optional[List[Any]] = Field(default_factory=list)
    errors: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    messages: Optional[List[Any]] = Field(default_factory=list)

    # Baseline and tool execution
    baseline_results: Optional[Dict[str, Any]] = Field(default_factory=dict)
    baseline_cycle_done: Optional[bool] = False
    pending_tool_calls: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    # Control flow
    iteration_count: Optional[int] = 0
    degraded_mode: Optional[bool] = False
    human_feedback_pending: Optional[bool] = False
    human_feedback_processed: Optional[bool] = False

    # Performance and caching
    metrics: Optional[Dict[str, Any]] = Field(default_factory=dict)
    cache_keys: Optional[List[str]] = Field(default_factory=list)
    enrich_cache: Optional[Dict[str, List[Dict[str, Any]]]] = Field(default_factory=dict)
    cache: Optional[Dict[str, Any]] = Field(default_factory=dict)
    cache_hits: Optional[List[str]] = Field(default_factory=list)

    # Streaming and progress
    streaming_enabled: Optional[bool] = False
    summarize_progress: Optional[float] = 0.0

    # Risk and compliance
    risk_assessment: Optional[Dict[str, Any]] = Field(default_factory=dict)
    compliance_check: Optional[Dict[str, Any]] = Field(default_factory=dict)

    # Metadata
    host_id: Optional[str] = None
    current_stage: Optional[str] = "initializing"
    start_time: Optional[str] = None
    final_metrics: Optional[Dict[str, Any]] = Field(default_factory=dict)

    # Provider configuration
    llm_provider_mode: Optional[str] = "normal"

    class Config:
        """Pydantic configuration for flexible validation."""
        extra = "allow"  # Allow additional fields for extensibility


def normalize_graph_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a GraphState dict to ensure all mandatory keys exist with proper defaults.

    This function ensures deterministic behavior by guaranteeing that all expected
    keys are present and have appropriate default values, preventing None-handling
    scatter throughout the codebase.

    Args:
        state: Raw GraphState dict that may have missing or None keys

    Returns:
        Normalized GraphState dict with all mandatory keys present
    """
    # Filter out None values to let Pydantic use defaults
    filtered_state = {k: v for k, v in state.items() if v is not None}

    # Create normalized state using Pydantic schema defaults
    normalized = GraphStateSchema(**filtered_state).model_dump()

    # Only set start_time if it's not already present and not explicitly None
    if normalized.get("start_time") is None and "start_time" not in state:
        normalized["start_time"] = None  # Keep as None for empty states

    return normalized


def validate_graph_state(state: Dict[str, Any]) -> bool:
    """Validate that a GraphState dict conforms to the expected schema.

    Args:
        state: GraphState dict to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        GraphStateSchema(**state)
        return True
    except Exception:
        return False


def get_graph_state_defaults() -> Dict[str, Any]:
    """Get the default values for all GraphState fields.

    Returns:
        Dict containing default values for all GraphState fields
    """
    return GraphStateSchema().model_dump()
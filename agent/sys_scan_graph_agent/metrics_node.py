"""
Node Telemetry API for LangGraph Observability

Provides standardized telemetry collection for all graph nodes including:
- Per-node execution timings
- Call counters and invocation tracking
- Deterministic invocation IDs for traceability
- Performance metrics aggregation
"""

import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Optional
from datetime import datetime

from .graph_state import normalize_graph_state


class NodeTelemetry:
    """Handles telemetry collection for graph nodes."""

    def __init__(self):
        self.node_calls: Dict[str, int] = {}
        self.node_durations: Dict[str, list] = {}
        self.last_node_ts: Optional[float] = None
        self.last_node_id: Optional[str] = None

    def increment_call(self, node_name: str) -> None:
        """Increment call counter for a node."""
        self.node_calls[node_name] = self.node_calls.get(node_name, 0) + 1

    def add_duration(self, node_name: str, duration: float) -> None:
        """Add execution duration for a node."""
        if node_name not in self.node_durations:
            self.node_durations[node_name] = []
        self.node_durations[node_name].append(duration)

    def update_last_execution(self, node_name: str) -> str:
        """Update last execution timestamp and generate invocation ID."""
        self.last_node_ts = time.time()
        self.last_node_id = f"{node_name}_{uuid.uuid4().hex[:8]}_{int(self.last_node_ts)}"
        return self.last_node_id

    def get_metrics(self) -> Dict[str, Any]:
        """Get current telemetry metrics."""
        return {
            'node_calls': self.node_calls.copy(),
            'node_durations': self.node_durations.copy(),
            'last_node_ts': self.last_node_ts,
            'last_node_id': self.last_node_id,
            'total_calls': sum(self.node_calls.values()),
            'avg_durations': {
                name: sum(durs) / len(durs) if durs else 0.0
                for name, durs in self.node_durations.items()
            }
        }


# Global telemetry instance
_telemetry = NodeTelemetry()


def get_node_telemetry() -> NodeTelemetry:
    """Get the global node telemetry instance."""
    return _telemetry


@contextmanager
def time_node(state: Any, node_name: str):
    """
    Context manager for timing node execution and collecting telemetry.

    Args:
        state: GraphState dictionary (can be GraphState TypedDict or Dict[str, Any])
        node_name: Name of the node being executed

    Usage:
        with time_node(state, 'enrich_findings'):
            # Node execution code here
            pass
    """
    # Normalize state to ensure consistent structure
    normalized_state = normalize_graph_state(state)  # type: ignore

    # Initialize metrics in state if not present
    if 'metrics' not in normalized_state:
        normalized_state['metrics'] = {}

    metrics = normalized_state['metrics']

    # Initialize telemetry sections if not present
    if 'node_calls' not in metrics:
        metrics['node_calls'] = {}
    if 'node_durations' not in metrics:
        metrics['node_durations'] = {}
    if 'node_timestamps' not in metrics:
        metrics['node_timestamps'] = {}
    if 'node_ids' not in metrics:
        metrics['node_ids'] = {}

    # Record start time
    start_time = time.time()
    invocation_id = get_node_telemetry().update_last_execution(node_name)

    try:
        # Update global telemetry
        get_node_telemetry().increment_call(node_name)

        # Update state metrics
        metrics['node_calls'][node_name] = metrics['node_calls'].get(node_name, 0) + 1
        metrics['node_timestamps'][node_name] = start_time
        metrics['node_ids'][node_name] = invocation_id

        # Add to state's metrics
        if 'telemetry' not in metrics:
            metrics['telemetry'] = {}
        metrics['telemetry']['current_node'] = node_name
        metrics['telemetry']['invocation_id'] = invocation_id

        yield normalized_state  # type: ignore

    finally:
        # Record end time and duration
        end_time = time.time()
        duration = end_time - start_time

        # Update global telemetry
        get_node_telemetry().add_duration(node_name, duration)

        # Update state metrics
        if node_name not in metrics['node_durations']:
            metrics['node_durations'][node_name] = []
        metrics['node_durations'][node_name].append(duration)

        # Update completion telemetry
        metrics['telemetry']['last_duration'] = duration
        metrics['telemetry']['last_completion_ts'] = end_time

        # Update state's last metrics
        metrics['last_node_ts'] = end_time
        metrics['last_node_id'] = invocation_id


def get_node_metrics_summary(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get a summary of node metrics from the current state.

    Args:
        state: GraphState dictionary

    Returns:
        Dictionary with node metrics summary
    """
    normalized_state = normalize_graph_state(state)  # type: ignore
    metrics = normalized_state.get('metrics', {})

    summary = {
        'total_nodes_executed': len(metrics.get('node_calls', {})),
        'total_calls': sum(metrics.get('node_calls', {}).values()),
        'node_breakdown': {},
        'performance_stats': {},
        'telemetry_info': metrics.get('telemetry', {})
    }

    # Build node breakdown
    node_calls = metrics.get('node_calls', {})
    node_durations = metrics.get('node_durations', {})

    for node_name in node_calls:
        durations = node_durations.get(node_name, [])
        summary['node_breakdown'][node_name] = {
            'calls': node_calls[node_name],
            'total_duration': sum(durations),
            'avg_duration': sum(durations) / len(durations) if durations else 0.0,
            'min_duration': min(durations) if durations else 0.0,
            'max_duration': max(durations) if durations else 0.0,
            'last_invocation_id': metrics.get('node_ids', {}).get(node_name)
        }

    # Performance stats
    all_durations = []
    for durations in node_durations.values():
        all_durations.extend(durations)

    if all_durations:
        summary['performance_stats'] = {
            'total_execution_time': sum(all_durations),
            'avg_node_duration': sum(all_durations) / len(all_durations),
            'slowest_node': max(
                [(name, sum(durs)) for name, durs in node_durations.items()],
                key=lambda x: x[1]
            )[0] if node_durations else None
        }

    return summary


def reset_node_telemetry() -> None:
    """Reset global node telemetry (useful for testing)."""
    global _telemetry
    _telemetry = NodeTelemetry()
"""
Performance Baseline for LangGraph Node Telemetry

Tracks expected performance metrics for node execution times and call patterns.
Used for detecting performance regressions in CI/CD pipelines.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import statistics

# Expected baseline metrics (will be updated by CI)
BASELINE_METRICS = {
    "version": "1.0",
    "last_updated": "2024-01-01T00:00:00Z",
    "expected_node_durations": {
        "enhanced_enrich_findings": {"mean": 0.5, "std": 0.1, "max": 1.0},
        "enhanced_summarize_host_state": {"mean": 1.0, "std": 0.2, "max": 2.0},
        "enhanced_suggest_rules": {"mean": 0.8, "std": 0.15, "max": 1.5},
        "advanced_router": {"mean": 0.05, "std": 0.01, "max": 0.1},
        "error_handler": {"mean": 0.1, "std": 0.05, "max": 0.5},
        "human_feedback_node": {"mean": 0.2, "std": 0.1, "max": 1.0},
        "tool_coordinator": {"mean": 0.3, "std": 0.1, "max": 0.8},
        "risk_analyzer": {"mean": 0.4, "std": 0.1, "max": 1.0},
        "compliance_checker": {"mean": 0.3, "std": 0.1, "max": 0.8},
        "cache_manager": {"mean": 0.1, "std": 0.05, "max": 0.3},
        "metrics_collector": {"mean": 0.2, "std": 0.05, "max": 0.5}
    },
    "expected_call_patterns": {
        "total_nodes_min": 8,
        "total_nodes_max": 15,
        "cache_hit_rate_min": 0.0,
        "cache_hit_rate_max": 0.9
    },
    "performance_thresholds": {
        "max_regression_factor": 2.0,  # Max 2x slowdown allowed
        "min_calls_threshold": 1,      # Minimum calls per node
        "max_duration_threshold": 10.0  # Max 10 seconds per node
    }
}


def load_baseline(baseline_path: str = "build/performance_baseline.json") -> Dict[str, Any]:
    """Load performance baseline from file."""
    path = Path(baseline_path)
    if path.exists():
        with open(path, 'r') as f:
            return json.load(f)
    return BASELINE_METRICS.copy()


def save_baseline(baseline: Dict[str, Any], baseline_path: str = "build/performance_baseline.json") -> None:
    """Save performance baseline to file."""
    path = Path(baseline_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    baseline["last_updated"] = datetime.now().isoformat()
    with open(path, 'w') as f:
        json.dump(baseline, f, indent=2)


def check_performance_regression(current_metrics: Dict[str, Any],
                               baseline_path: str = "build/performance_baseline.json") -> Dict[str, Any]:
    """
    Check for performance regressions against baseline.

    Args:
        current_metrics: Current run metrics
        baseline_path: Path to baseline file

    Returns:
        Dictionary with regression analysis results
    """
    baseline = load_baseline(baseline_path)
    results = {
        "regression_detected": False,
        "violations": [],
        "summary": {},
        "recommendations": []
    }

    # Check node duration regressions
    node_durations = current_metrics.get('node_breakdown', {})
    expected_durations = baseline.get('expected_node_durations', {})

    for node_name, node_data in node_durations.items():
        if node_name in expected_durations:
            expected = expected_durations[node_name]
            actual_mean = node_data['avg_duration']

            # Check for regression (actual > expected_max * regression_factor)
            max_allowed = expected['max'] * baseline['performance_thresholds']['max_regression_factor']
            if actual_mean > max_allowed:
                results["regression_detected"] = True
                results["violations"].append({
                    "type": "duration_regression",
                    "node": node_name,
                    "expected_max": expected['max'],
                    "actual": actual_mean,
                    "regression_factor": actual_mean / expected['max']
                })

    # Check call pattern anomalies
    total_nodes = current_metrics.get('total_nodes_executed', 0)
    thresholds = baseline['performance_thresholds']

    if total_nodes < baseline['expected_call_patterns']['total_nodes_min']:
        results["violations"].append({
            "type": "insufficient_nodes",
            "expected_min": baseline['expected_call_patterns']['total_nodes_min'],
            "actual": total_nodes
        })

    if total_nodes > baseline['expected_call_patterns']['total_nodes_max']:
        results["violations"].append({
            "type": "excessive_nodes",
            "expected_max": baseline['expected_call_patterns']['total_nodes_max'],
            "actual": total_nodes
        })

    # Check cache hit rate
    cache_hit_rate = current_metrics.get('cache_hit_rate', 0.0)
    if cache_hit_rate < baseline['expected_call_patterns']['cache_hit_rate_min']:
        results["violations"].append({
            "type": "low_cache_hit_rate",
            "expected_min": baseline['expected_call_patterns']['cache_hit_rate_min'],
            "actual": cache_hit_rate
        })

    # Generate summary
    results["summary"] = {
        "total_violations": len(results["violations"]),
        "nodes_analyzed": len(node_durations),
        "cache_hit_rate": cache_hit_rate,
        "total_execution_time": current_metrics.get('performance_stats', {}).get('total_execution_time', 0)
    }

    # Set regression_detected if any violations found
    if results["violations"]:
        results["regression_detected"] = True

    # Generate recommendations
    if results["violations"]:
        results["recommendations"].append("Performance regression detected. Consider optimizing slow nodes.")
        if any(v['type'] == 'duration_regression' for v in results["violations"]):
            results["recommendations"].append("Review node implementations for optimization opportunities.")
        if any(v['type'] in ['insufficient_nodes', 'excessive_nodes'] for v in results["violations"]):
            results["recommendations"].append("Verify graph workflow configuration.")

    return results


def update_baseline_from_metrics(current_metrics: Dict[str, Any],
                               baseline_path: str = "build/performance_baseline.json",
                               smoothing_factor: float = 0.1) -> None:
    """
    Update baseline with current metrics using exponential smoothing.

    Args:
        current_metrics: Current run metrics
        baseline_path: Path to baseline file
        smoothing_factor: Smoothing factor for exponential moving average (0-1)
    """
    baseline = load_baseline(baseline_path)
    node_durations = current_metrics.get('node_breakdown', {})

    # Update expected durations with smoothing
    for node_name, node_data in node_durations.items():
        if node_name not in baseline['expected_node_durations']:
            baseline['expected_node_durations'][node_name] = {
                "mean": node_data['avg_duration'],
                "std": 0.0,
                "max": node_data['max_duration']
            }
        else:
            expected = baseline['expected_node_durations'][node_name]
            # Exponential smoothing
            expected['mean'] = (1 - smoothing_factor) * expected['mean'] + smoothing_factor * node_data['avg_duration']
            expected['max'] = max(expected['max'], node_data['max_duration'])

    save_baseline(baseline, baseline_path)


if __name__ == "__main__":
    # Example usage
    print("Performance Baseline Management")
    print("Current baseline:", load_baseline())
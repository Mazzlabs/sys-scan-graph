"""
Metrics Exporter for LangGraph Observability

Provides functionality to export node telemetry and performance metrics
in various formats including Prometheus, JSON, and CSV for monitoring
and analysis purposes.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

from .graph_state import normalize_graph_state
from .metrics_node import get_node_telemetry, get_node_metrics_summary

logger = logging.getLogger(__name__)


def export_prometheus(state: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """
    Export metrics in Prometheus format for monitoring systems.

    Args:
        state: GraphState dictionary with metrics
        output_path: Optional file path to write metrics

    Returns:
        Prometheus-formatted metrics string
    """
    normalized_state = normalize_graph_state(state)  # type: ignore
    metrics = normalized_state.get('metrics', {})

    prometheus_lines = [
        "# HELP sys_scan_graph_node_calls_total Total number of times each node was called",
        "# TYPE sys_scan_graph_node_calls_total counter",
    ]

    # Node call counters
    node_calls = metrics.get('node_calls', {})
    for node_name, count in node_calls.items():
        prometheus_lines.append(f'sys_scan_graph_node_calls_total{{node="{node_name}"}} {count}')

    # Node duration histograms
    prometheus_lines.extend([
        "",
        "# HELP sys_scan_graph_node_duration_seconds Time spent in each node",
        "# TYPE sys_scan_graph_node_duration_seconds histogram",
    ])

    node_durations = metrics.get('node_durations', {})
    for node_name, durations in node_durations.items():
        if durations:
            prometheus_lines.append(f'sys_scan_graph_node_duration_seconds_count{{node="{node_name}"}} {len(durations)}')
            prometheus_lines.append(f'sys_scan_graph_node_duration_seconds_sum{{node="{node_name}"}} {sum(durations)}')

            # Calculate percentiles
            sorted_durations = sorted(durations)
            p50 = sorted_durations[len(sorted_durations) // 2]
            p95 = sorted_durations[int(len(sorted_durations) * 0.95)]
            p99 = sorted_durations[int(len(sorted_durations) * 0.99)]

            prometheus_lines.extend([
                f'sys_scan_graph_node_duration_seconds{{node="{node_name}",quantile="0.5"}} {p50}',
                f'sys_scan_graph_node_duration_seconds{{node="{node_name}",quantile="0.95"}} {p95}',
                f'sys_scan_graph_node_duration_seconds{{node="{node_name}",quantile="0.99"}} {p99}',
            ])

    # Global telemetry metrics
    global_telemetry = get_node_telemetry().get_metrics()
    prometheus_lines.extend([
        "",
        "# HELP sys_scan_graph_total_calls Total calls across all nodes",
        "# TYPE sys_scan_graph_total_calls counter",
        f"sys_scan_graph_total_calls {global_telemetry.get('total_calls', 0)}",
        "",
        "# HELP sys_scan_graph_cache_hit_rate Cache hit rate percentage",
        "# TYPE sys_scan_graph_cache_hit_rate gauge",
        f"sys_scan_graph_cache_hit_rate {metrics.get('cache_hit_rate', 0) * 100}",
    ])

    prometheus_output = "\n".join(prometheus_lines)

    if output_path:
        Path(output_path).write_text(prometheus_output)
        logger.info(f"Prometheus metrics exported to {output_path}")

    return prometheus_output


def write_metrics_json(state: Dict[str, Any], output_path: str) -> None:
    """
    Export comprehensive metrics to JSON file.

    Args:
        state: GraphState dictionary with metrics
        output_path: File path to write JSON metrics
    """
    normalized_state = normalize_graph_state(state)  # type: ignore

    # Get comprehensive metrics summary
    summary = get_node_metrics_summary(normalized_state)

    # Add global telemetry
    global_telemetry = get_node_telemetry().get_metrics()
    summary['global_telemetry'] = global_telemetry

    # Add export metadata
    summary['export_timestamp'] = time.time()
    summary['export_time_iso'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    # Write to file
    with open(output_path, 'w') as f:
        json.dump(summary, f, indent=2, default=str)

    logger.info(f"JSON metrics exported to {output_path}")


def export_metrics_csv(state: Dict[str, Any], output_path: str) -> None:
    """
    Export metrics in CSV format for spreadsheet analysis.

    Args:
        state: GraphState dictionary with metrics
        output_path: File path to write CSV metrics
    """
    import csv

    normalized_state = normalize_graph_state(state)  # type: ignore
    metrics = normalized_state.get('metrics', {})

    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write header
        writer.writerow(['Node', 'Calls', 'Total_Duration', 'Avg_Duration', 'Min_Duration', 'Max_Duration', 'Last_Invocation_ID'])

        # Write node data
        node_calls = metrics.get('node_calls', {})
        node_durations = metrics.get('node_durations', {})
        node_ids = metrics.get('node_ids', {})

        for node_name in node_calls:
            calls = node_calls[node_name]
            durations = node_durations.get(node_name, [])
            invocation_id = node_ids.get(node_name, '')

            if durations:
                total_duration = sum(durations)
                avg_duration = total_duration / len(durations)
                min_duration = min(durations)
                max_duration = max(durations)
            else:
                total_duration = avg_duration = min_duration = max_duration = 0.0

            writer.writerow([
                node_name, calls, total_duration, avg_duration,
                min_duration, max_duration, invocation_id
            ])

    logger.info(f"CSV metrics exported to {output_path}")


def print_metrics_summary(state: Dict[str, Any]) -> None:
    """
    Print a human-readable metrics summary to console.

    Args:
        state: GraphState dictionary with metrics
    """
    summary = get_node_metrics_summary(state)

    print("\n" + "="*60)
    print("LANGGRAPH NODE TELEMETRY SUMMARY")
    print("="*60)

    print(f"Total Nodes Executed: {summary['total_nodes_executed']}")
    print(f"Total Calls: {summary['total_calls']}")

    if summary.get('performance_stats'):
        perf = summary['performance_stats']
        print(f"Total Execution Time: {perf['total_execution_time']:.3f}s")
        print(f"Average Node Duration: {perf['avg_node_duration']:.3f}s")
        if perf.get('slowest_node'):
            print(f"Slowest Node: {perf['slowest_node']}")

    print("\nNode Breakdown:")
    print("-" * 40)
    for node_name, node_data in summary.get('node_breakdown', {}).items():
        print(f"{node_name}:")
        print(f"  Calls: {node_data['calls']}")
        print(f"  Total Duration: {node_data['total_duration']:.3f}s")
        print(f"  Avg Duration: {node_data['avg_duration']:.3f}s")
        print(f"  Min/Max: {node_data['min_duration']:.3f}s / {node_data['max_duration']:.3f}s")
        if node_data.get('last_invocation_id'):
            print(f"  Last ID: {node_data['last_invocation_id']}")
        print()

    telemetry = summary.get('telemetry_info', {})
    if telemetry:
        print("Current Telemetry State:")
        print(f"  Current Node: {telemetry.get('current_node', 'N/A')}")
        print(f"  Invocation ID: {telemetry.get('invocation_id', 'N/A')}")
        if telemetry.get('last_duration'):
            print(f"  Last Duration: {telemetry['last_duration']:.3f}s")

    print("="*60)


def export_all_formats(state: Dict[str, Any], base_path: str) -> Dict[str, str]:
    """
    Export metrics in all supported formats.

    Args:
        state: GraphState dictionary with metrics
        base_path: Base path for output files (without extension)

    Returns:
        Dictionary mapping format names to file paths
    """
    path_obj = Path(base_path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)

    exported_files = {}

    # JSON export
    json_path = f"{base_path}.json"
    write_metrics_json(state, json_path)
    exported_files['json'] = json_path

    # CSV export
    csv_path = f"{base_path}.csv"
    export_metrics_csv(state, csv_path)
    exported_files['csv'] = csv_path

    # Prometheus export
    prometheus_path = f"{base_path}.prom"
    export_prometheus(state, prometheus_path)
    exported_files['prometheus'] = prometheus_path

    return exported_files


__all__ = [
    'export_prometheus',
    'write_metrics_json',
    'export_metrics_csv',
    'print_metrics_summary',
    'export_all_formats'
]
"""Simple metrics collection module for the agent pipeline."""

import json
import os
import time
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)

class MetricsCollector:
    """Simple metrics collector for timing and logging operations."""

    def __init__(self):
        self.metrics = {}
        self.start_times = {}

    @contextmanager
    def time_stage(self, stage_name: str):
        """Context manager to time a stage of processing."""
        start_time = time.time()
        try:
            yield
        finally:
            end_time = time.time()
            duration = end_time - start_time
            logger.debug(f"Stage '{stage_name}' completed in {duration:.3f}s")
            if stage_name not in self.metrics:
                self.metrics[stage_name] = []
            self.metrics[stage_name].append(duration)

    def incr(self, metric_name: str, value: int = 1) -> None:
        """Increment a counter metric."""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = 0
        self.metrics[metric_name] += value

    def snapshot(self):
        """Take a snapshot of current metrics."""
        return {
            'metrics': self.metrics.copy(),
            'timestamp': time.time(),
            'total_stages': len(self.metrics)
        }

    @classmethod
    def load_baseline(cls, path: str):
        """Load baseline metrics from file."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @classmethod
    def compare_to_baseline(cls, current, baseline, threshold: float):
        """Compare current metrics to baseline and detect regressions."""
        if not baseline:
            return []
        
        regressions = []
        current_metrics = current.get('metrics', {})
        baseline_metrics = baseline.get('metrics', {})
        
        for stage, current_time in current_metrics.items():
            baseline_time = baseline_metrics.get(stage)
            if baseline_time:
                # Handle both single values and lists
                if isinstance(current_time, list):
                    current_avg = sum(current_time) / len(current_time) if current_time else 0
                else:
                    current_avg = current_time
                
                if isinstance(baseline_time, list):
                    baseline_avg = sum(baseline_time) / len(baseline_time) if baseline_time else 0
                else:
                    baseline_avg = baseline_time
                
                if current_avg > baseline_avg * (1 + threshold):
                    regressions.append({
                        'stage': stage,
                        'current_time': current_avg,
                        'baseline_time': baseline_avg,
                        'regression_pct': ((current_avg - baseline_avg) / baseline_avg) * 100
                    })
        
        return regressions

    @classmethod
    def save_baseline(cls, path: str, snapshot):
        """Save metrics snapshot as baseline."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(snapshot, f, indent=2)
        except Exception:
            pass  # Silently fail if we can't save baseline

    def reset(self):
        """Reset all metrics."""
        self.metrics.clear()

# Global metrics collector instance
_metrics_collector = None

def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector

def set_metrics_collector(collector: MetricsCollector):
    """Set the global metrics collector instance."""
    global _metrics_collector
    _metrics_collector = collector

__all__ = ['MetricsCollector', 'get_metrics_collector', 'set_metrics_collector']

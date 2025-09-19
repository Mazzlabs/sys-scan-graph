"""
Registry for managing correlation producers.
"""

from typing import Dict, List, Any, Optional
from base_correlation_producer import BaseCorrelationProducer
from process_network_correlation_producer import ProcessNetworkCorrelationProducer
from filesystem_correlation_producer import FileSystemCorrelationProducer
from kernel_correlation_producer import KernelCorrelationProducer

# Import parallel processing utilities
try:
    from parallel_processor import process_correlations_parallel, get_parallel_processor
    PARALLEL_AVAILABLE = True
except ImportError:
    PARALLEL_AVAILABLE = False

class CorrelationRegistry:
    """Registry for all correlation producers."""

    def __init__(self):
        self.correlation_producers: Dict[str, BaseCorrelationProducer] = {}
        self._register_default_producers()

    def _register_default_producers(self):
        """Register all default correlation producers."""
        self.register_correlation_producer("process_network", ProcessNetworkCorrelationProducer())
        self.register_correlation_producer("filesystem", FileSystemCorrelationProducer())
        self.register_correlation_producer("kernel", KernelCorrelationProducer())

    def register_correlation_producer(self, name: str, producer: BaseCorrelationProducer):
        """Register a correlation producer."""
        self.correlation_producers[name] = producer

    def get_correlation_producer(self, name: str) -> BaseCorrelationProducer:
        """Get a correlation producer by name."""
        if name not in self.correlation_producers:
            raise ValueError(f"Correlation producer '{name}' not found")
        return self.correlation_producers[name]

    def list_correlation_producers(self) -> List[str]:
        """List all registered correlation producers."""
        return list(self.correlation_producers.keys())

    def analyze_all_correlations(self, findings: Dict[str, List[Dict[str, Any]]], conservative_parallel: bool = True, gpu_optimized: Optional[bool] = None) -> List[Dict[str, Any]]:
        """
        Run all correlation producers and collect their findings.

        Args:
            findings: Dictionary mapping scanner types to their findings
            conservative_parallel: Whether to use conservative parallel processing
            gpu_optimized: Whether to use GPU-optimized parallel processing

        Returns:
            List of all correlation findings from all producers
        """
        # Use parallel processing if available and beneficial
        if PARALLEL_AVAILABLE and len(self.correlation_producers) > 1:
            processor = get_parallel_processor(conservative_parallel, gpu_optimized)
            print(f"🔄 Using parallel processing for {len(self.correlation_producers)} correlation producers ({processor.max_workers} workers)")
            return process_correlations_parallel(self.correlation_producers, findings, "Analyzing correlations", processor)
        else:
            # Fallback to sequential processing
            if not PARALLEL_AVAILABLE:
                print("📝 Parallel processing not available, using sequential processing")
            else:
                print("📝 Small number of correlation producers, using sequential processing")

            all_correlations = []
            for name, producer in self.correlation_producers.items():
                try:
                    correlations = producer.analyze_correlations(findings)
                    all_correlations.extend(correlations)
                    print(f"  {name}: Generated {len(correlations)} correlations")
                except Exception as e:
                    print(f"  ERROR in {name}: {e}")

            return all_correlations

    def get_correlation_summary(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of correlation analysis results."""
        summary = {
            "total_correlations": len(correlations),
            "correlation_types": {},
            "severity_distribution": {},
            "risk_score_ranges": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0
            },
            "top_correlations": []
        }

        for correlation in correlations:
            # Count by correlation type
            corr_type = correlation.get("correlation_type", "unknown")
            summary["correlation_types"][corr_type] = summary["correlation_types"].get(corr_type, 0) + 1

            # Count by severity
            severity = correlation.get("severity", "unknown")
            summary["severity_distribution"][severity] = summary["severity_distribution"].get(severity, 0) + 1

            # Count by risk score ranges
            risk_score = correlation.get("risk_score", 0)
            if risk_score >= 80:
                summary["risk_score_ranges"]["critical"] += 1
            elif risk_score >= 60:
                summary["risk_score_ranges"]["high"] += 1
            elif risk_score >= 40:
                summary["risk_score_ranges"]["medium"] += 1
            else:
                summary["risk_score_ranges"]["low"] += 1

        # Get top correlations by risk score
        sorted_correlations = sorted(correlations, key=lambda x: x.get("risk_score", 0), reverse=True)
        summary["top_correlations"] = [
            {
                "title": c.get("title", ""),
                "risk_score": c.get("risk_score", 0),
                "severity": c.get("severity", ""),
                "correlation_type": c.get("correlation_type", "")
            }
            for c in sorted_correlations[:5]
        ]

        return summary

# Global correlation registry instance
correlation_registry = CorrelationRegistry()
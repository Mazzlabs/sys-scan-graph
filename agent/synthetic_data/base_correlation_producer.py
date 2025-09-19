"""
Base correlation producer for analyzing relationships between different scanner findings.
"""

from typing import Dict, List, Any, Optional
import uuid
from datetime import datetime
import random

class BaseCorrelationProducer:
    """Base class for correlation producers that analyze relationships between findings."""

    def __init__(self, name: str):
        self.name = name
        self.correlation_id = f"corr_{name}_{uuid.uuid4().hex[:8]}"

    def analyze_correlations(self, findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Analyze correlations between findings from different scanners.

        Args:
            findings: Dictionary mapping scanner types to their findings

        Returns:
            List of correlation findings
        """
        raise NotImplementedError("Subclasses must implement analyze_correlations")

    def _create_correlation_finding(
        self,
        title: str,
        description: str,
        severity: str,
        risk_score: int,
        related_findings: List[str],
        correlation_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a standardized correlation finding."""
        return {
            "id": f"{self.correlation_id}_{uuid.uuid4().hex[:8]}",
            "title": title,
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": risk_score,
            "description": description,
            "metadata": metadata or {},
            "operational_error": False,
            "category": "correlation",
            "tags": ["correlation", correlation_type, self.name],
            "risk_subscores": {
                "impact": random.uniform(0.1, 0.9),
                "exposure": random.uniform(0.1, 0.8),
                "anomaly": random.uniform(0.2, 0.95),
                "confidence": random.uniform(0.7, 0.95)
            },
            "correlation_refs": related_findings,
            "baseline_status": "new",
            "severity_source": "correlation",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.3, 0.9),
            "graph_degree": len(related_findings),
            "cluster_id": self.correlation_id,
            "rationale": f"Correlation analysis by {self.name} producer",
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None,
            "correlation_type": correlation_type,
            "correlation_strength": self._calculate_correlation_strength(related_findings),
            "timestamp": datetime.now().isoformat()
        }

    def _calculate_correlation_strength(self, related_findings: List[str]) -> float:
        """Calculate the strength of a correlation based on number of related findings."""
        base_strength = min(len(related_findings) * 0.2, 0.8)
        return base_strength + random.uniform(0.1, 0.2)

    def _find_related_findings(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        criteria: Dict[str, Any]
    ) -> List[str]:
        """Find findings that match specific criteria."""
        related_ids = []

        for scanner_type, scanner_findings in findings.items():
            for finding in scanner_findings:
                if self._matches_criteria(finding, criteria):
                    related_ids.append(finding["id"])

        return related_ids

    def _matches_criteria(self, finding: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
        """Check if a finding matches the given criteria."""
        for key, value in criteria.items():
            if key not in finding:
                return False

            finding_value = finding[key]

            if isinstance(value, dict):
                # Nested criteria
                if not isinstance(finding_value, dict):
                    return False
                if not self._matches_criteria(finding_value, value):
                    return False
            elif isinstance(value, list):
                # Value must be in list
                if finding_value not in value:
                    return False
            else:
                # Direct value match
                if finding_value != value:
                    return False

        return True
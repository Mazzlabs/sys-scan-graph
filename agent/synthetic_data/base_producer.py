"""
Base producer class for synthetic data generation.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import json
import random
from datetime import datetime
import uuid

class BaseProducer(ABC):
    """Base class for all synthetic data producers."""

    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.scenarios = {
            'normal': 0.7,      # 70% normal findings
            'suspicious': 0.2,  # 20% suspicious
            'malicious': 0.08,  # 8% malicious
            'edge_case': 0.02   # 2% edge cases
        }

    @abstractmethod
    def generate_findings(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate synthetic findings for this scanner.

        Args:
            count: Number of findings to generate

        Returns:
            List of finding dictionaries matching the ground truth schema
        """
        pass

    def _generate_base_finding(self, finding_id: str, title: str, severity: str,
                              risk_score: int, base_severity_score: int,
                              description: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a base finding structure."""
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": base_severity_score,
            "description": description,
            "metadata": metadata,
            "operational_error": False,
            "category": self.scanner_name,
            "tags": self._generate_tags(severity),
            "risk_subscores": self._generate_risk_subscores(severity),
            "correlation_refs": [],
            "baseline_status": random.choice(["new", "existing", "unknown"]),
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": self._calculate_probability_actionable(risk_score),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_tags(self, severity: str) -> List[str]:
        """Generate appropriate tags based on severity."""
        base_tags = [self.scanner_name, f"baseline:{random.choice(['new', 'existing'])}"]

        if severity in ['high', 'critical']:
            base_tags.extend(['high_priority', 'needs_attention'])
        elif severity == 'medium':
            base_tags.append('moderate_risk')
        elif severity in ['low', 'info']:
            base_tags.append('low_priority')

        return base_tags

    def _generate_risk_subscores(self, severity: str) -> Dict[str, float]:
        """Generate risk subscores based on severity."""
        severity_multipliers = {
            'info': 0.2,
            'low': 0.4,
            'medium': 0.6,
            'high': 0.8,
            'critical': 1.0
        }

        multiplier = severity_multipliers.get(severity, 0.5)

        return {
            "impact": round(random.uniform(0.1, 1.0) * multiplier, 2),
            "exposure": round(random.uniform(0.1, 1.0) * multiplier, 2),
            "anomaly": round(random.uniform(0.1, 1.0) * multiplier, 2),
            "confidence": round(random.uniform(0.7, 0.95), 2)
        }

    def _calculate_probability_actionable(self, risk_score: int) -> float:
        """Calculate probability that finding is actionable."""
        # Higher risk scores are more likely to be actionable
        base_prob = risk_score / 100.0
        return round(min(1.0, base_prob + random.uniform(-0.1, 0.1)), 3)

    def _choose_scenario(self) -> str:
        """Randomly choose a scenario based on weights."""
        rand = random.random()
        cumulative = 0.0
        for scenario, weight in self.scenarios.items():
            cumulative += weight
            if rand <= cumulative:
                return scenario
        return 'normal'
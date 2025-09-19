"""
Schema verifier to ensure synthetic data matches the ground truth schema.
"""

from typing import Dict, List, Any, Tuple
import json
import os
from base_verifier import BaseVerifier

class SchemaVerifier(BaseVerifier):
    """Verifier for JSON schema compliance."""

    def __init__(self):
        super().__init__("SchemaVerifier")
        self.schema_path = os.path.join(os.path.dirname(__file__), "ground_truth_schema.json")
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict[str, Any]:
        """Load the ground truth schema."""
        try:
            with open(self.schema_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def verify(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Verify data against the schema."""
        issues = []

        # Check required top-level fields
        required_fields = ["version", "enriched_findings", "correlations", "reductions", "summaries", "actions"]
        for field in required_fields:
            if field not in data:
                issues.append(self._log_issue(f"Missing required field: {field}"))

        # Check version
        if "version" in data and data["version"] != "ground_truth_v1":
            issues.append(self._log_issue(f"Invalid version: {data.get('version')}"))

        # Check enriched_findings structure
        if "enriched_findings" in data:
            findings = data["enriched_findings"]
            if not isinstance(findings, list):
                issues.append(self._log_issue("enriched_findings must be a list"))
            else:
                for i, finding in enumerate(findings):
                    finding_issues = self._verify_finding_structure(finding, i)
                    issues.extend(finding_issues)

        # Check correlations structure
        if "correlations" in data:
            correlations = data["correlations"]
            if not isinstance(correlations, list):
                issues.append(self._log_issue("correlations must be a list"))
            else:
                for i, correlation in enumerate(correlations):
                    correlation_issues = self._verify_correlation_structure(correlation, i)
                    issues.extend(correlation_issues)

        return len(issues) == 0, issues

    def _verify_finding_structure(self, finding: Dict[str, Any], index: int) -> List[str]:
        """Verify a single finding's structure."""
        issues = []
        required_fields = ["id", "title", "severity", "risk_score", "base_severity_score", "description", "metadata", "risk_subscores", "probability_actionable", "baseline_status", "tags"]

        for field in required_fields:
            if field not in finding:
                issues.append(self._log_issue(f"Finding {index}: Missing required field '{field}'"))

        # Check severity values
        if "severity" in finding:
            valid_severities = ["info", "low", "medium", "high", "critical"]
            if finding["severity"] not in valid_severities:
                issues.append(self._log_issue(f"Finding {index}: Invalid severity '{finding['severity']}'"))

        # Check risk scores are integers
        for score_field in ["risk_score", "base_severity_score"]:
            if score_field in finding and not isinstance(finding[score_field], int):
                issues.append(self._log_issue(f"Finding {index}: {score_field} must be an integer"))

        # Check risk_subscores structure
        if "risk_subscores" in finding:
            subscores = finding["risk_subscores"]
            required_subscores = ["impact", "exposure", "anomaly", "confidence"]
            if not isinstance(subscores, dict):
                issues.append(self._log_issue(f"Finding {index}: risk_subscores must be a dict"))
            else:
                for subscore in required_subscores:
                    if subscore not in subscores:
                        issues.append(self._log_issue(f"Finding {index}: Missing risk_subscore '{subscore}'"))

        return issues

    def _verify_correlation_structure(self, correlation: Dict[str, Any], index: int) -> List[str]:
        """Verify a single correlation's structure."""
        issues = []
        required_fields = ["id", "title", "related_finding_ids"]

        for field in required_fields:
            if field not in correlation:
                issues.append(self._log_issue(f"Correlation {index}: Missing required field '{field}'"))

        if "related_finding_ids" in correlation and not isinstance(correlation["related_finding_ids"], list):
            issues.append(self._log_issue(f"Correlation {index}: related_finding_ids must be a list"))

        return issues
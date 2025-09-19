"""
Coherence verifier to ensure synthetic data is logically consistent.
"""

from typing import Dict, List, Any, Tuple
from collections import defaultdict
from base_verifier import BaseVerifier

class CoherenceVerifier(BaseVerifier):
    """Verifier for logical coherence in synthetic data."""

    def __init__(self):
        super().__init__("CoherenceVerifier")

    def verify(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Verify coherence of synthetic data."""
        issues = []

        if "enriched_findings" not in data:
            return True, []  # No findings to check

        findings = data["enriched_findings"]

        # Check for duplicate IDs
        ids = [f.get("id") for f in findings if f.get("id")]
        duplicate_ids = [id for id in ids if ids.count(id) > 1]
        if duplicate_ids:
            issues.append(self._log_issue(f"Duplicate finding IDs: {set(duplicate_ids)}"))

        # Check process-network coherence
        process_issues = self._verify_process_network_coherence(findings)
        issues.extend(process_issues)

        # Check severity-risk score coherence
        severity_issues = self._verify_severity_risk_coherence(findings)
        issues.extend(severity_issues)

        # Check correlation references
        correlation_issues = self._verify_correlation_references(data)
        issues.extend(correlation_issues)

        return len(issues) == 0, issues

    def _verify_process_network_coherence(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Verify coherence between process and network findings."""
        issues = []

        # Group findings by category
        process_findings = [f for f in findings if f.get("category") == "processes"]
        network_findings = [f for f in findings if f.get("category") == "network"]

        # Check for suspicious processes with network activity
        suspicious_processes = [f for f in process_findings if f.get("severity") in ["high", "critical"]]
        suspicious_network = [f for f in network_findings if f.get("severity") in ["high", "critical"]]

        # If we have suspicious processes, we should have some network activity
        if suspicious_processes and not suspicious_network:
            issues.append(self._log_issue("Suspicious processes without corresponding network activity"))

        # Check for network connections without processes
        network_with_processes = []
        for net_finding in network_findings:
            metadata = net_finding.get("metadata", {})
            if "process" in metadata:
                network_with_processes.append(net_finding)

        if network_with_processes and not process_findings:
            issues.append(self._log_issue("Network findings reference processes but no process findings exist"))

        return issues

    def _verify_severity_risk_coherence(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Verify that severity levels match risk scores."""
        issues = []

        severity_ranges = {
            "info": (0, 20),
            "low": (10, 40),
            "medium": (30, 70),
            "high": (60, 90),
            "critical": (80, 100)
        }

        for finding in findings:
            severity = finding.get("severity")
            risk_score = finding.get("risk_score")

            if severity and risk_score is not None:
                min_score, max_score = severity_ranges.get(severity, (0, 100))
                if not (min_score <= risk_score <= max_score):
                    issues.append(self._log_issue(f"Finding {finding.get('id')}: Risk score {risk_score} doesn't match severity '{severity}' (expected {min_score}-{max_score})"))

        return issues

    def _verify_correlation_references(self, data: Dict[str, Any]) -> List[str]:
        """Verify that correlation references are valid."""
        issues = []

        findings = data.get("enriched_findings", [])
        correlations = data.get("correlations", [])

        # Build set of finding IDs
        finding_ids = {f.get("id") for f in findings if f.get("id")}

        # Check correlation references
        for correlation in correlations:
            related_ids = correlation.get("related_finding_ids", [])
            for related_id in related_ids:
                if related_id not in finding_ids:
                    issues.append(self._log_issue(f"Correlation {correlation.get('id')} references non-existent finding '{related_id}'"))

        # Check finding correlation references
        for finding in findings:
            correlation_refs = finding.get("correlation_refs", [])
            for ref in correlation_refs:
                correlation_ids = {c.get("id") for c in correlations if c.get("id")}
                if ref not in correlation_ids:
                    issues.append(self._log_issue(f"Finding {finding.get('id')} references non-existent correlation '{ref}'"))

        return issues
"""
Main synthetic data generator that orchestrates producers and verifiers.
"""

from typing import Dict, List, Any, Optional
import json
import os
from datetime import datetime
from producer_registry import registry
from verifier_orchestrator import VerifierOrchestrator

class SyntheticDataGenerator:
    """Main generator for synthetic security scan data."""

    def __init__(self):
        self.producer_registry = registry
        self.verifier_orchestrator = VerifierOrchestrator()

    def generate_ground_truth_data(self,
                                 producer_counts: Optional[Dict[str, int]] = None,
                                 verify: bool = True,
                                 max_iterations: int = 5) -> Dict[str, Any]:
        """Generate complete ground truth data.

        Args:
            producer_counts: Number of findings per producer
            verify: Whether to verify the generated data
            max_iterations: Maximum iterations to try generating valid data

        Returns:
            Complete ground truth data dictionary
        """
        for iteration in range(max_iterations):
            # Generate findings from all producers
            producer_results = self.producer_registry.generate_all_findings(producer_counts)

            # Flatten all findings
            all_findings = []
            for producer_name, findings in producer_results.items():
                all_findings.extend(findings)

            # Create ground truth structure
            ground_truth = self._create_ground_truth_structure(all_findings)

            # Verify if requested
            if verify:
                is_valid, issues = self.verifier_orchestrator.verify(ground_truth)

                if is_valid:
                    print(f"Generated valid data on iteration {iteration + 1}")
                    return ground_truth
                else:
                    print(f"Iteration {iteration + 1} failed verification:")
                    for verifier_name, verifier_issues in issues.items():
                        if verifier_issues:
                            print(f"  {verifier_name}: {len(verifier_issues)} issues")
                            for issue in verifier_issues[:3]:  # Show first 3 issues
                                print(f"    - {issue}")
                    if iteration < max_iterations - 1:
                        print("Retrying...")
                        continue
            else:
                return ground_truth

        # If we get here, all iterations failed
        raise ValueError(f"Failed to generate valid data after {max_iterations} iterations")

    def _create_ground_truth_structure(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create the complete ground truth data structure."""
        # Generate some basic correlations
        correlations = self._generate_basic_correlations(findings)

        # Create reductions summary
        reductions = self._generate_reductions(findings)

        # Create summaries
        summaries = self._generate_summaries(findings)

        # Create actions
        actions = self._generate_actions(findings)

        return {
            "version": "ground_truth_v1",
            "enriched_findings": findings,
            "correlations": correlations,
            "reductions": reductions,
            "summaries": summaries,
            "actions": actions,
            "raw_reference": None,
            "correlation_graph": None,
            "followups": [],
            "enrichment_results": {},
            "multi_host_correlation": [],
            "integrity": None
        }

    def _generate_basic_correlations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate basic correlations between findings."""
        correlations = []

        # Simple correlation: group high-severity findings
        high_severity_findings = [f for f in findings if f.get("severity") in ["high", "critical"]]

        if len(high_severity_findings) > 1:
            correlation = {
                "id": "high_severity_cluster",
                "title": "Cluster of high-severity security findings",
                "rationale": "Multiple high-severity findings detected that may be related",
                "related_finding_ids": [f["id"] for f in high_severity_findings[:5]],  # Limit to 5
                "risk_score_delta": 10,
                "tags": ["cluster", "high_severity"],
                "severity": "high",
                "exposure_tags": ["multiple_findings"]
            }
            correlations.append(correlation)

        return correlations

    def _generate_reductions(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate reductions summary."""
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "module_summary": None,
            "suid_summary": None,
            "network_summary": None,
            "top_findings": findings[:10] if findings else [],  # Top 10 findings
            "top_risks": None
        }

    def _generate_summaries(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary narratives."""
        total_findings = len(findings)
        high_severity = len([f for f in findings if f.get("severity") in ["high", "critical"]])

        executive_summary = f"Security assessment identified {total_findings} findings, including {high_severity} high/critical severity issues."

        return {
            "executive_summary": executive_summary,
            "analyst": None,
            "consistency_findings": None,
            "triage_summary": None,
            "action_narrative": None,
            "metrics": None,
            "causal_hypotheses": None,
            "attack_coverage": None
        }

    def _generate_actions(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommended actions."""
        actions = []

        high_findings = [f for f in findings if f.get("severity") in ["high", "critical"]]

        if high_findings:
            actions.append({
                "id": "investigate_high_severity",
                "title": "Investigate high-severity findings",
                "description": f"Review {len(high_findings)} high-severity security findings",
                "priority": "high",
                "severity": "high"
            })

        return actions

    def save_to_file(self, data: Dict[str, Any], filepath: str):
        """Save ground truth data to JSON file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Saved synthetic data to {filepath}")

    def load_from_file(self, filepath: str) -> Dict[str, Any]:
        """Load ground truth data from JSON file."""
        with open(filepath, 'r') as f:
            return json.load(f)
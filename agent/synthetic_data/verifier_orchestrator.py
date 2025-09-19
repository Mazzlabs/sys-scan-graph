"""
Verifier orchestrator to run all verifiers and aggregate results.
"""

from typing import Dict, List, Any, Tuple
from base_verifier import BaseVerifier
from schema_verifier import SchemaVerifier
from coherence_verifier import CoherenceVerifier
from realism_verifier import RealismVerifier
from abundance_verifier import AbundanceVerifier

class VerifierOrchestrator:
    """Orchestrates all verifiers for comprehensive validation."""

    def __init__(self):
        self.verifiers: List[BaseVerifier] = [
            SchemaVerifier(),
            CoherenceVerifier(),
            RealismVerifier(),
            AbundanceVerifier()
        ]

    def verify(self, data: Dict[str, Any]) -> Tuple[bool, Dict[str, List[str]]]:
        """Run all verifiers and aggregate results.

        Args:
            data: The synthetic data to verify

        Returns:
            Tuple of (overall_valid, dict of verifier_name -> issues)
        """
        all_issues = {}
        overall_valid = True

        for verifier in self.verifiers:
            is_valid, issues = verifier.verify(data)
            all_issues[verifier.name] = issues

            if not is_valid:
                overall_valid = False

        return overall_valid, all_issues

    def get_summary(self, verification_results: Dict[str, List[str]]) -> Dict[str, Any]:
        """Get a summary of verification results."""
        total_issues = sum(len(issues) for issues in verification_results.values())
        verifiers_passed = sum(1 for issues in verification_results.values() if len(issues) == 0)

        return {
            "total_issues": total_issues,
            "verifiers_passed": verifiers_passed,
            "total_verifiers": len(self.verifiers),
            "pass_rate": verifiers_passed / len(self.verifiers) if self.verifiers else 0,
            "issues_by_verifier": {name: len(issues) for name, issues in verification_results.items()}
        }

    def suggest_improvements(self, verification_results: Dict[str, List[str]]) -> List[str]:
        """Suggest improvements based on verification results."""
        suggestions = []

        for verifier_name, issues in verification_results.items():
            if issues:
                if verifier_name == "SchemaVerifier":
                    suggestions.append("Fix schema compliance issues - ensure all required fields are present")
                elif verifier_name == "CoherenceVerifier":
                    suggestions.append("Improve logical coherence - check relationships between findings")
                elif verifier_name == "RealismVerifier":
                    suggestions.append("Enhance realism - vary findings and use more realistic values")
                elif verifier_name == "AbundanceVerifier":
                    suggestions.append("Reduce over-abundance - limit similar findings and balance distributions")

        if not suggestions:
            suggestions.append("All verifications passed - data looks good!")

        return suggestions
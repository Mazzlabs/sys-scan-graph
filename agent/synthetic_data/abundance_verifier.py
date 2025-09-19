"""
Abundance verifier to prevent over-generation of similar findings.
"""

from typing import Dict, List, Any, Tuple
from collections import Counter
from base_verifier import BaseVerifier

class AbundanceVerifier(BaseVerifier):
    """Verifier to prevent over-abundance of similar findings."""

    def __init__(self):
        super().__init__("AbundanceVerifier")
        self.max_similar_findings = 50  # Maximum similar findings
        self.max_category_percentage = 0.8  # Max percentage of findings in one category

    def verify(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Verify abundance constraints."""
        issues = []

        if "enriched_findings" not in data:
            return True, []

        findings = data["enriched_findings"]
        total_findings = len(findings)

        if total_findings == 0:
            return True, []

        # Check category distribution
        category_issues = self._verify_category_distribution(findings, total_findings)
        issues.extend(category_issues)

        # Check for over-abundance of similar findings
        similarity_issues = self._verify_similar_findings_abundance(findings)
        issues.extend(similarity_issues)

        # Check severity distribution balance
        severity_issues = self._verify_severity_balance(findings, total_findings)
        issues.extend(severity_issues)

        return len(issues) == 0, issues

    def _verify_category_distribution(self, findings: List[Dict[str, Any]], total: int) -> List[str]:
        """Verify that no category dominates excessively."""
        issues = []

        categories = [f.get("category", "unknown") for f in findings]
        category_counts = Counter(categories)

        for category, count in category_counts.items():
            percentage = count / total
            if percentage > self.max_category_percentage:
                issues.append(self._log_issue(f"Category '{category}' dominates: {percentage:.1%} of findings (max {self.max_category_percentage:.1%})"))

        return issues

    def _verify_similar_findings_abundance(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Verify that similar findings aren't over-abundant."""
        issues = []

        # Group by title patterns
        title_patterns = []
        for finding in findings:
            title = finding.get("title", "")
            # Extract key pattern from title
            if ":" in title:
                pattern = title.split(":")[0].strip()
            else:
                pattern = title[:20]  # First 20 chars
            title_patterns.append(pattern)

        pattern_counts = Counter(title_patterns)

        for pattern, count in pattern_counts.items():
            if count > self.max_similar_findings:
                issues.append(self._log_issue(f"Over-abundance of similar findings: '{pattern}' appears {count} times (max {self.max_similar_findings})"))

        # Check for identical metadata
        metadata_hashes = []
        for finding in findings:
            metadata = finding.get("metadata", {})
            # Create a simple hash of key metadata
            metadata_str = str(sorted(metadata.items()))
            metadata_hashes.append(metadata_str)

        metadata_counts = Counter(metadata_hashes)
        for metadata_hash, count in metadata_counts.items():
            if count > self.max_similar_findings:
                issues.append(self._log_issue(f"Over-abundance of identical metadata: {count} findings with same metadata (max {self.max_similar_findings})"))

        return issues

    def _verify_severity_balance(self, findings: List[Dict[str, Any]], total: int) -> List[str]:
        """Verify that severity distribution is balanced."""
        issues = []

        severities = [f.get("severity", "unknown") for f in findings]
        severity_counts = Counter(severities)

        # Critical findings should be rare
        critical_count = severity_counts.get("critical", 0)
        if critical_count > total * 0.1:  # More than 10% critical
            issues.append(self._log_issue(f"Too many critical findings: {critical_count} ({critical_count/total:.1%})"))

        # High findings should also be limited
        high_count = severity_counts.get("high", 0)
        if high_count > total * 0.2:  # More than 20% high
            issues.append(self._log_issue(f"Too many high findings: {high_count} ({high_count/total:.1%})"))

        # Should have some info findings
        info_count = severity_counts.get("info", 0)
        if info_count < total * 0.3:  # Less than 30% info
            issues.append(self._log_issue(f"Too few info findings: {info_count} ({info_count/total:.1%}) - should be at least 30%"))

        return issues
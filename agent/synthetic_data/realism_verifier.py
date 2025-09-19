"""
Realism verifier to ensure synthetic data looks like real scanner output.
"""

from typing import Dict, List, Any, Tuple
import random
from base_verifier import BaseVerifier

class RealismVerifier(BaseVerifier):
    """Verifier for realism of synthetic data."""

    def __init__(self):
        super().__init__("RealismVerifier")
        self.realistic_patterns = {
            "processes": {
                "common_commands": ["/usr/sbin/sshd", "/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/apache2"],
                "realistic_pids": list(range(1000, 10000)),
                "realistic_users": ["root", "www-data", "user", "systemd"]
            },
            "network": {
                "common_ports": [22, 80, 443, 3306, 5432],
                "realistic_states": ["LISTEN", "ESTABLISHED", "TIME_WAIT"],
                "realistic_addresses": ["0.0.0.0", "127.0.0.1", "::", "::1"]
            }
        }

    def verify(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Verify realism of synthetic data."""
        issues = []

        if "enriched_findings" not in data:
            return True, []

        findings = data["enriched_findings"]

        # Check overall distribution
        distribution_issues = self._verify_distribution_realism(findings)
        issues.extend(distribution_issues)

        # Check individual finding realism
        for i, finding in enumerate(findings):
            finding_issues = self._verify_finding_realism(finding, i)
            issues.extend(finding_issues)

        # Check metadata realism
        metadata_issues = self._verify_metadata_realism(findings)
        issues.extend(metadata_issues)

        return len(issues) == 0, issues

    def _verify_distribution_realism(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Verify that the distribution of findings looks realistic."""
        issues = []

        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        total_findings = len(findings)

        # Realistic distributions (percentages)
        realistic_distributions = {
            "info": (0.4, 0.8),      # 40-80% info
            "low": (0.1, 0.3),      # 10-30% low
            "medium": (0.05, 0.2),  # 5-20% medium
            "high": (0.01, 0.1),    # 1-10% high
            "critical": (0.0, 0.05) # 0-5% critical
        }

        for severity, (min_pct, max_pct) in realistic_distributions.items():
            count = severity_counts.get(severity, 0)
            pct = count / total_findings if total_findings > 0 else 0

            if not (min_pct <= pct <= max_pct):
                issues.append(self._log_issue(f"Severity '{severity}' distribution unrealistic: {pct:.1%} (expected {min_pct:.0%}-{max_pct:.0%})"))

        return issues

    def _verify_finding_realism(self, finding: Dict[str, Any], index: int) -> List[str]:
        """Verify realism of individual finding."""
        issues = []

        category = finding.get("category")
        metadata = finding.get("metadata", {})

        if category == "processes":
            issues.extend(self._verify_process_realism(metadata, index))
        elif category == "network":
            issues.extend(self._verify_network_realism(metadata, index))

        # Check description length
        description = finding.get("description", "")
        if len(description) < 10:
            issues.append(self._log_issue(f"Finding {index}: Description too short"))
        elif len(description) > 500:
            issues.append(self._log_issue(f"Finding {index}: Description too long"))

        # Check title format
        title = finding.get("title", "")
        if not title or len(title) < 5:
            issues.append(self._log_issue(f"Finding {index}: Title too short or empty"))

        return issues

    def _verify_process_realism(self, metadata: Dict[str, Any], index: int) -> List[str]:
        """Verify process finding realism."""
        issues = []

        pid = metadata.get("pid")
        if pid is not None:
            if not isinstance(pid, int) or pid < 1 or pid > 99999:
                issues.append(self._log_issue(f"Finding {index}: Unrealistic PID {pid}"))

        command = metadata.get("command", "")
        if command:
            # Check for obviously fake commands
            fake_indicators = ["/fake/", "/malware/", "/evil/"]
            for indicator in fake_indicators:
                if indicator in command:
                    issues.append(self._log_issue(f"Finding {index}: Obviously fake command '{command}'"))

        return issues

    def _verify_network_realism(self, metadata: Dict[str, Any], index: int) -> List[str]:
        """Verify network finding realism."""
        issues = []

        port = metadata.get("port")
        if port is not None:
            if not isinstance(port, int) or port < 1 or port > 65535:
                issues.append(self._log_issue(f"Finding {index}: Invalid port {port}"))

        state = metadata.get("state", "")
        valid_states = ["LISTEN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "CLOSED"]
        if state and state not in valid_states:
            issues.append(self._log_issue(f"Finding {index}: Invalid socket state '{state}'"))

        return issues

    def _verify_metadata_realism(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Verify overall metadata realism."""
        issues = []

        # Check for too many identical metadata values
        metadata_fields = ["command", "port", "protocol", "user"]
        for field in metadata_fields:
            values = []
            for finding in findings:
                metadata = finding.get("metadata", {})
                value = metadata.get(field)
                if value is not None:
                    values.append(str(value))

            # Check for over-repetition
            if values:
                most_common = max(set(values), key=values.count)
                frequency = values.count(most_common) / len(values)
                if frequency > 0.8:  # More than 80% same value
                    issues.append(self._log_issue(f"Over-repetition of {field}='{most_common}' ({frequency:.1%})"))

        return issues
"""
Process-Network correlation producer for analyzing relationships between process and network findings.
"""

from typing import Dict, List, Any
import random
from base_correlation_producer import BaseCorrelationProducer

class ProcessNetworkCorrelationProducer(BaseCorrelationProducer):
    """Analyzes correlations between process and network scanner findings."""

    def __init__(self):
        super().__init__("process_network")

    def analyze_correlations(self, findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Analyze correlations between process and network findings."""
        correlations = []

        process_findings = findings.get("processes", [])
        network_findings = findings.get("network", [])

        if not process_findings or not network_findings:
            return correlations

        # Analyze each process for network correlations
        for process in process_findings:
            process_correlations = self._analyze_process_correlations(process, network_findings)
            correlations.extend(process_correlations)

        return correlations

    def _analyze_process_correlations(
        self,
        process: Dict[str, Any],
        network_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze correlations for a specific process."""
        correlations = []
        process_name = process.get("metadata", {}).get("command", "").split("/")[-1]
        process_pid = process.get("metadata", {}).get("pid")

        # Look for suspicious process + suspicious network activity
        if process.get("severity") in ["medium", "high", "critical"]:
            related_network = self._find_suspicious_network_activity(network_findings)

            if related_network:
                correlation = self._create_suspicious_process_network_correlation(
                    process, related_network
                )
                correlations.append(correlation)

        # Look for known malicious processes with C2 communications
        if self._is_potential_malware(process_name):
            c2_connections = self._find_c2_connections(network_findings)

            if c2_connections:
                correlation = self._create_malware_c2_correlation(
                    process, c2_connections
                )
                correlations.append(correlation)

        # Look for processes with unusual port usage
        unusual_ports = self._find_unusual_port_usage(network_findings, process_pid)

        if unusual_ports:
            correlation = self._create_unusual_port_correlation(
                process, unusual_ports
            )
            correlations.append(correlation)

        return correlations

    def _find_suspicious_network_activity(self, network_findings: List[Dict[str, Any]]) -> List[str]:
        """Find suspicious network activity."""
        suspicious_ids = []

        for finding in network_findings:
            if finding.get("severity") in ["medium", "high", "critical"]:
                suspicious_ids.append(finding["id"])

        return suspicious_ids[:3]  # Limit to top 3

    def _find_c2_connections(self, network_findings: List[Dict[str, Any]]) -> List[str]:
        """Find potential C2 (Command and Control) connections."""
        c2_ids = []

        for finding in network_findings:
            title = finding.get("title", "").lower()
            if "c2" in title or "command" in title or "control" in title:
                c2_ids.append(finding["id"])

        return c2_ids

    def _find_unusual_port_usage(self, network_findings: List[Dict[str, Any]], process_pid: str) -> List[str]:
        """Find unusual port usage that might be related to a process."""
        unusual_ids = []

        for finding in network_findings:
            metadata = finding.get("metadata", {})
            port = metadata.get("port")

            # Consider ports above 1024 as potentially unusual for system processes
            if port and port > 1024 and finding.get("severity") in ["low", "medium"]:
                unusual_ids.append(finding["id"])

        return unusual_ids[:2]  # Limit to top 2

    def _is_potential_malware(self, process_name: str) -> bool:
        """Check if a process name suggests potential malware."""
        suspicious_patterns = [
            "backdoor", "trojan", "virus", "malware", "exploit",
            "shell", "netcat", "ncat", "socat", "cryptominer"
        ]

        process_lower = process_name.lower()
        return any(pattern in process_lower for pattern in suspicious_patterns)

    def _create_suspicious_process_network_correlation(
        self,
        process: Dict[str, Any],
        network_ids: List[str]
    ) -> Dict[str, Any]:
        """Create correlation finding for suspicious process + network activity."""
        process_name = process.get("metadata", {}).get("command", "").split("/")[-1]

        return self._create_correlation_finding(
            title=f"Suspicious process with network activity: {process_name}",
            description=f"Suspicious process '{process_name}' detected alongside unusual network activity",
            severity="high",
            risk_score=75,
            related_findings=[process["id"]] + network_ids,
            correlation_type="process_network_suspicious",
            metadata={
                "process_name": process_name,
                "network_activities": len(network_ids),
                "correlation_reason": "suspicious_process_network_activity"
            }
        )

    def _create_malware_c2_correlation(
        self,
        process: Dict[str, Any],
        c2_ids: List[str]
    ) -> Dict[str, Any]:
        """Create correlation finding for malware with C2 communications."""
        process_name = process.get("metadata", {}).get("command", "").split("/")[-1]

        return self._create_correlation_finding(
            title=f"Potential malware C2 communication: {process_name}",
            description=f"Process '{process_name}' showing signs of malware with C2 communications",
            severity="critical",
            risk_score=95,
            related_findings=[process["id"]] + c2_ids,
            correlation_type="malware_c2",
            metadata={
                "process_name": process_name,
                "c2_connections": len(c2_ids),
                "correlation_reason": "malware_c2_communication"
            }
        )

    def _create_unusual_port_correlation(
        self,
        process: Dict[str, Any],
        port_ids: List[str]
    ) -> Dict[str, Any]:
        """Create correlation finding for unusual port usage."""
        process_name = process.get("metadata", {}).get("command", "").split("/")[-1]

        return self._create_correlation_finding(
            title=f"Unusual port usage by process: {process_name}",
            description=f"Process '{process_name}' using unusual network ports",
            severity="medium",
            risk_score=55,
            related_findings=[process["id"]] + port_ids,
            correlation_type="unusual_port_usage",
            metadata={
                "process_name": process_name,
                "unusual_ports": len(port_ids),
                "correlation_reason": "unusual_port_activity"
            }
        )
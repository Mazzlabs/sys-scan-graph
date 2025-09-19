"""
Network scanner producer for generating synthetic network-related findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class NetworkProducer(BaseProducer):
    """Producer for synthetic network scanner findings."""

    def __init__(self):
        super().__init__("network")
        self.common_ports = [22, 80, 443, 3306, 5432, 6379, 27017]
        self.suspicious_ports = [4444, 1337, 6667, 31337, 12345, 54321]
        self.protocols = ['tcp', 'udp', 'tcp6', 'udp6']

    def generate_findings(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate synthetic network findings."""
        findings = []

        for i in range(count):
            scenario = self._choose_scenario()
            finding = self._generate_network_finding(scenario, i)
            findings.append(finding)

        return findings

    def _generate_network_finding(self, scenario: str, index: int) -> Dict[str, Any]:
        """Generate a single network finding based on scenario."""

        if scenario == 'normal':
            return self._generate_normal_network(index)
        elif scenario == 'suspicious':
            return self._generate_suspicious_network(index)
        elif scenario == 'malicious':
            return self._generate_malicious_network(index)
        elif scenario == 'edge_case':
            return self._generate_edge_case_network(index)
        else:
            return self._generate_normal_network(index)

    def _generate_normal_network(self, index: int) -> Dict[str, Any]:
        """Generate a normal network finding."""
        port = random.choice(self.common_ports)
        protocol = random.choice(['tcp', 'tcp6'])
        state = random.choice(['LISTEN', 'ESTABLISHED'])

        return self._generate_base_finding(
            finding_id=f"net_normal_{port}_{index}",
            title=f"Normal network service on port {port}",
            severity="info",
            risk_score=10,
            base_severity_score=10,
            description=f"Standard service listening on port {port}/{protocol}",
            metadata={
                "port": port,
                "protocol": protocol,
                "state": state,
                "local_address": f"0.0.0.0:{port}" if protocol in ['tcp', 'udp'] else f"[::]:{port}",
                "foreign_address": "0.0.0.0:0" if state == 'LISTEN' else f"192.168.1.{random.randint(1,254)}:{random.randint(1024,65535)}",
                "inode": random.randint(10000, 99999)
            }
        )

    def _generate_suspicious_network(self, index: int) -> Dict[str, Any]:
        """Generate a suspicious network finding."""
        port = random.choice(self.suspicious_ports)
        protocol = random.choice(self.protocols)

        return self._generate_base_finding(
            finding_id=f"net_susp_{port}_{index}",
            title=f"Suspicious port {port} open",
            severity="medium",
            risk_score=60,
            base_severity_score=60,
            description=f"Unusual port {port} is listening, commonly associated with malware",
            metadata={
                "port": port,
                "protocol": protocol,
                "state": "LISTEN",
                "local_address": f"0.0.0.0:{port}",
                "foreign_address": "0.0.0.0:0",
                "inode": random.randint(100000, 999999),
                "process": f"/usr/bin/nc -l {port}" if random.random() < 0.5 else None
            }
        )

    def _generate_malicious_network(self, index: int) -> Dict[str, Any]:
        """Generate a malicious network finding."""
        port = random.randint(1, 65535)
        protocol = 'tcp'

        return self._generate_base_finding(
            finding_id=f"net_mal_{port}_{index}",
            title=f"Malicious C2 communication detected",
            severity="critical",
            risk_score=95,
            base_severity_score=95,
            description=f"Outbound connection to known malicious IP on port {port}",
            metadata={
                "port": port,
                "protocol": protocol,
                "state": "ESTABLISHED",
                "local_address": f"192.168.1.{random.randint(1,254)}:{random.randint(1024,65535)}",
                "foreign_address": f"203.0.113.{random.randint(1,254)}:{port}",
                "inode": random.randint(1000000, 9999999),
                "process": "/tmp/.backdoor",
                "malicious_ip": True,
                "c2_indicator": True
            }
        )

    def _generate_edge_case_network(self, index: int) -> Dict[str, Any]:
        """Generate an edge case network finding."""
        edge_cases = [
            {"port": 0, "desc": "Port 0 (invalid port)"},
            {"port": 65535, "desc": "Maximum port number"},
            {"port": random.randint(1, 65535), "protocol": "unknown", "desc": "Unknown protocol"},
            {"port": 22, "state": "UNKNOWN", "desc": "Unknown socket state"}
        ]
        edge_case = random.choice(edge_cases)

        return self._generate_base_finding(
            finding_id=f"net_edge_{index}",
            title="Network edge case",
            severity="low",
            risk_score=20,
            base_severity_score=20,
            description=edge_case["desc"],
            metadata={
                "port": edge_case.get("port", 0),
                "protocol": edge_case.get("protocol", "tcp"),
                "state": edge_case.get("state", "LISTEN"),
                "local_address": f"127.0.0.1:{edge_case.get('port', 0)}",
                "foreign_address": "0.0.0.0:0",
                "inode": 0 if edge_case.get("port") == 0 else random.randint(10000, 99999)
            }
        )
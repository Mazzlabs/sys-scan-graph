"""
Kernel parameters producer for generating synthetic kernel parameter-related findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class KernelParamsProducer(BaseProducer):
    """Producer for synthetic kernel parameter scanner findings."""

    def __init__(self):
        super().__init__("kernel_params")

    def _generate_normal_kernel_param(self) -> Dict[str, Any]:
        """Generate a normal kernel parameter finding."""
        normal_params = [
            "/proc/sys/kernel/kptr_restrict",
            "/proc/sys/kernel/randomize_va_space",
            "/proc/sys/kernel/dmesg_restrict",
            "/proc/sys/kernel/panic_on_oops",
            "/proc/sys/kernel/panic",
            "/proc/sys/net/ipv4/tcp_syncookies",
            "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            "/proc/sys/net/ipv4/conf/all/accept_redirects",
            "/proc/sys/net/ipv4/conf/all/send_redirects"
        ]

        param = random.choice(normal_params)
        param_name = param.split("/")[-1]

        # Most normal params should be properly configured
        current_value = "1" if random.random() < 0.8 else "0"
        desired_value = "1"

        return {
            "id": f"kernel_{param_name}_{uuid.uuid4().hex[:8]}",
            "title": param_name,
            "severity": "info",
            "risk_score": 10,
            "base_severity_score": 10,
            "description": self._get_param_description(param_name),
            "metadata": {
                "current": current_value,
                "desired": desired_value,
                "status": "ok" if current_value == desired_value else "mismatch"
            },
            "operational_error": False,
            "category": "kernel_params",
            "tags": ["kernel", "security", "configuration"],
            "risk_subscores": {
                "impact": random.uniform(0.05, 0.15),
                "exposure": random.uniform(0.02, 0.08),
                "anomaly": random.uniform(0.1, 0.2),
                "confidence": random.uniform(0.85, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.01, 0.1),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 10,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_suspicious_kernel_param(self) -> Dict[str, Any]:
        """Generate a suspicious kernel parameter finding."""
        suspicious_params = [
            "/proc/sys/net/ipv4/ip_forward",
            "/proc/sys/net/ipv4/conf/all/rp_filter",
            "/proc/sys/net/ipv4/conf/all/accept_source_route",
            "/proc/sys/net/ipv4/conf/all/accept_redirects",
            "/proc/sys/net/ipv4/conf/all/secure_redirects",
            "/proc/sys/kernel/core_uses_pid",
            "/proc/sys/kernel/sysrq"
        ]

        param = random.choice(suspicious_params)
        param_name = param.split("/")[-1]

        # These are often misconfigured
        current_value = "1" if random.random() < 0.6 else "0"
        desired_value = "0" if param_name in ["ip_forward", "accept_source_route", "accept_redirects", "secure_redirects"] else "1"

        severity = "low" if abs(int(current_value) - int(desired_value)) == 0 else "medium"
        risk_score = 30 if severity == "low" else 50

        return {
            "id": f"kernel_{param_name}_{uuid.uuid4().hex[:8]}",
            "title": param_name,
            "severity": severity,
            "risk_score": risk_score,
            "base_severity_score": risk_score,
            "description": self._get_param_description(param_name),
            "metadata": {
                "current": current_value,
                "desired": desired_value,
                "status": "mismatch" if current_value != desired_value else "ok"
            },
            "operational_error": False,
            "category": "kernel_params",
            "tags": ["kernel", "security", "configuration", "suspicious"],
            "risk_subscores": {
                "impact": random.uniform(0.2, 0.4),
                "exposure": random.uniform(0.1, 0.3),
                "anomaly": random.uniform(0.3, 0.6),
                "confidence": random.uniform(0.7, 0.9)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.1, 0.3),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": risk_score,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_malicious_kernel_param(self) -> Dict[str, Any]:
        """Generate a malicious kernel parameter finding."""
        malicious_params = [
            "/proc/sys/net/ipv4/ip_forward",
            "/proc/sys/net/ipv4/conf/all/accept_source_route",
            "/proc/sys/net/ipv4/conf/all/accept_redirects",
            "/proc/sys/kernel/yama/ptrace_scope",
            "/proc/sys/fs/protected_hardlinks",
            "/proc/sys/fs/protected_symlinks"
        ]

        param = random.choice(malicious_params)
        param_name = param.split("/")[-1]

        # These are security-critical and often misconfigured
        current_value = "0"  # Usually the insecure value
        desired_value = "1"  # Usually the secure value

        return {
            "id": f"kernel_{param_name}_{uuid.uuid4().hex[:8]}",
            "title": param_name,
            "severity": "high",
            "risk_score": 80,
            "base_severity_score": 80,
            "description": self._get_param_description(param_name),
            "metadata": {
                "current": current_value,
                "desired": desired_value,
                "status": "mismatch"
            },
            "operational_error": False,
            "category": "kernel_params",
            "tags": ["kernel", "security", "configuration", "critical", "vulnerability"],
            "risk_subscores": {
                "impact": random.uniform(0.6, 0.9),
                "exposure": random.uniform(0.4, 0.7),
                "anomaly": random.uniform(0.7, 0.95),
                "confidence": random.uniform(0.8, 0.95)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.5, 0.8),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 80,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_edge_case_kernel_param(self) -> Dict[str, Any]:
        """Generate an edge case kernel parameter finding."""
        edge_params = [
            "/proc/sys/kernel/pid_max",
            "/proc/sys/kernel/threads-max",
            "/proc/sys/vm/max_map_count",
            "/proc/sys/fs/file-max"
        ]

        param = random.choice(edge_params)
        param_name = param.split("/")[-1]

        # Edge case: extremely high or low values
        if param_name == "pid_max":
            current_value = str(random.choice([10, 100, 10000000]))  # Very low or very high
            desired_value = "4194304"  # Default
        elif param_name == "threads-max":
            current_value = str(random.choice([10, 100, 10000000]))
            desired_value = "126226"
        else:
            current_value = str(random.choice([10, 100, 10000000]))
            desired_value = "65536"

        return {
            "id": f"kernel_{param_name}_{uuid.uuid4().hex[:8]}",
            "title": param_name,
            "severity": "medium",
            "risk_score": 40,
            "base_severity_score": 40,
            "description": f"{param_name} has unusual value",
            "metadata": {
                "current": current_value,
                "desired": desired_value,
                "status": "mismatch"
            },
            "operational_error": False,
            "category": "kernel_params",
            "tags": ["kernel", "configuration", "edge_case"],
            "risk_subscores": {
                "impact": random.uniform(0.3, 0.5),
                "exposure": random.uniform(0.1, 0.3),
                "anomaly": random.uniform(0.8, 0.95),
                "confidence": random.uniform(0.6, 0.8)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.2, 0.4),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 40,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _get_param_description(self, param_name: str) -> str:
        """Get description for a kernel parameter."""
        descriptions = {
            "kptr_restrict": "Kernel pointer addresses restricted",
            "randomize_va_space": "ASLR should be full (2)",
            "dmesg_restrict": "Restrict kernel log access",
            "panic_on_oops": "Panic on kernel oops",
            "panic": "Kernel panic timeout",
            "tcp_syncookies": "TCP SYN cookies enabled",
            "icmp_echo_ignore_broadcasts": "Ignore ICMP echo broadcasts",
            "accept_redirects": "Accept ICMP redirects",
            "send_redirects": "Send ICMP redirects",
            "ip_forward": "IP forwarding disabled unless a router",
            "rp_filter": "Reverse path filtering",
            "accept_source_route": "Accept source routed packets",
            "secure_redirects": "Accept secure ICMP redirects",
            "core_uses_pid": "Core dumps include PID",
            "sysrq": "SysRq key enabled",
            "ptrace_scope": "Ptrace scope restrictions",
            "protected_hardlinks": "Protect hardlinks",
            "protected_symlinks": "Protect symlinks",
            "pid_max": "Maximum PID value",
            "threads-max": "Maximum threads",
            "max_map_count": "Maximum memory map areas",
            "file-max": "Maximum open files"
        }
        return descriptions.get(param_name, f"Kernel parameter {param_name}")

    def generate_findings(self, count: int) -> List[Dict[str, Any]]:
        """Generate the specified number of kernel parameter findings."""
        findings = []

        for _ in range(count):
            scenario = self._choose_scenario()

            if scenario == "normal":
                finding = self._generate_normal_kernel_param()
            elif scenario == "suspicious":
                finding = self._generate_suspicious_kernel_param()
            elif scenario == "malicious":
                finding = self._generate_malicious_kernel_param()
            elif scenario == "edge_case":
                finding = self._generate_edge_case_kernel_param()

            findings.append(finding)

        return findings
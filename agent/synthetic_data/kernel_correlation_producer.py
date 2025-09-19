"""
Kernel correlation producer for analyzing relationships between kernel parameters, modules, and other findings.
"""

from typing import Dict, List, Any
import random
from base_correlation_producer import BaseCorrelationProducer

class KernelCorrelationProducer(BaseCorrelationProducer):
    """Analyzes correlations between kernel parameters, modules, and other scanner results."""

    def __init__(self):
        super().__init__("kernel")

    def analyze_correlations(self, findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Analyze correlations between kernel and other findings."""
        correlations = []

        kernel_params = findings.get("kernel_params", [])
        modules = findings.get("modules", [])
        processes = findings.get("processes", [])
        network = findings.get("network", [])
        mac = findings.get("mac", [])

        # Analyze kernel parameters with security implications
        if kernel_params:
            security_params = self._analyze_kernel_security_params(kernel_params)
            correlations.extend(security_params)

        # Analyze kernel modules with security context
        if modules:
            module_security = self._analyze_module_security_context(modules, kernel_params)
            correlations.extend(module_security)

        # Analyze kernel parameters with MAC status
        if kernel_params and mac:
            kernel_mac = self._analyze_kernel_mac_correlations(kernel_params, mac)
            correlations.extend(kernel_mac)

        # Analyze kernel hardening with process behavior
        if kernel_params and processes:
            kernel_process = self._analyze_kernel_process_correlations(kernel_params, processes)
            correlations.extend(kernel_process)

        return correlations

    def _analyze_kernel_security_params(self, kernel_params: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze kernel parameters for security implications."""
        correlations = []

        # Group parameters by security category
        security_groups = {
            "network_hardening": [],
            "memory_protection": [],
            "file_system": []
        }

        for param in kernel_params:
            title = param.get("title", "").lower()

            if any(word in title for word in ["tcp", "icmp", "ip", "net"]):
                security_groups["network_hardening"].append(param)
            elif any(word in title for word in ["vm", "memory", "mmap", "randomize"]):
                security_groups["memory_protection"].append(param)
            elif any(word in title for word in ["fs", "file", "dmesg", "ptrace"]):
                security_groups["file_system"].append(param)

        # Create correlations for weak security configurations
        for category, params in security_groups.items():
            weak_params = [p for p in params if p.get("severity") in ["medium", "high"]]

            if len(weak_params) >= 2:
                correlation = self._create_weak_security_params_correlation(
                    category, weak_params
                )
                correlations.append(correlation)

        return correlations

    def _analyze_module_security_context(
        self,
        modules: List[Dict[str, Any]],
        kernel_params: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze kernel modules in the context of kernel parameters."""
        correlations = []

        # Look for modules that might conflict with security parameters
        security_modules = [m for m in modules if m.get("severity") in ["medium", "high"]]

        if security_modules:
            # Check if there are related kernel parameters
            related_params = []
            for module in security_modules:
                module_name = module.get("title", "").replace("Module ", "").lower()

                for param in kernel_params:
                    param_title = param.get("title", "").lower()
                    if module_name in param_title or any(word in param_title for word in module_name.split()):
                        related_params.append(param["id"])

            if related_params:
                correlation = self._create_module_kernel_correlation(
                    security_modules, related_params
                )
                correlations.append(correlation)

        return correlations

    def _analyze_kernel_mac_correlations(
        self,
        kernel_params: List[Dict[str, Any]],
        mac_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze relationships between kernel parameters and MAC status."""
        correlations = []

        # Look for kernel parameters that affect MAC functionality
        mac_related_params = [
            p for p in kernel_params
            if any(word in p.get("title", "").lower() for word in ["selinux", "apparmor", "security"])
        ]

        if mac_related_params:
            # Check MAC status
            mac_disabled = any(
                f.get("metadata", {}).get("enabled") == "false" or
                f.get("severity") == "medium"
                for f in mac_findings
            )

            if mac_disabled:
                correlation = self._create_kernel_mac_correlation(
                    mac_related_params, mac_findings
                )
                correlations.append(correlation)

        return correlations

    def _analyze_kernel_process_correlations(
        self,
        kernel_params: List[Dict[str, Any]],
        processes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze relationships between kernel parameters and process behavior."""
        correlations = []

        # Look for kernel parameters that affect process execution
        process_related_params = [
            p for p in kernel_params
            if any(word in p.get("title", "").lower() for word in ["exec", "ptrace", "randomize", "mmap"])
        ]

        if process_related_params:
            # Find suspicious processes
            suspicious_processes = [
                p for p in processes
                if p.get("severity") in ["medium", "high", "critical"]
            ]

            if suspicious_processes:
                correlation = self._create_kernel_process_correlation(
                    process_related_params, suspicious_processes
                )
                correlations.append(correlation)

        return correlations

    def _create_weak_security_params_correlation(
        self,
        category: str,
        weak_params: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create correlation for weak security parameters in a category."""
        param_names = [p.get("title", "") for p in weak_params]

        return self._create_correlation_finding(
            title=f"Weak {category.replace('_', ' ')} configuration",
            description=f"Multiple kernel parameters in {category} category show weak security settings: {', '.join(param_names[:3])}",
            severity="high",
            risk_score=75,
            related_findings=[p["id"] for p in weak_params],
            correlation_type="weak_kernel_security",
            metadata={
                "category": category,
                "weak_parameters_count": len(weak_params),
                "parameter_names": param_names,
                "correlation_reason": "multiple_weak_security_settings"
            }
        )

    def _create_module_kernel_correlation(
        self,
        security_modules: List[Dict[str, Any]],
        param_ids: List[str]
    ) -> Dict[str, Any]:
        """Create correlation between security-related modules and kernel parameters."""
        module_names = [m.get("title", "") for m in security_modules]

        return self._create_correlation_finding(
            title="Security modules with kernel parameter conflicts",
            description=f"Security-related kernel modules detected with potentially conflicting kernel parameters: {', '.join(module_names[:2])}",
            severity="medium",
            risk_score=60,
            related_findings=[m["id"] for m in security_modules] + param_ids,
            correlation_type="module_kernel_conflict",
            metadata={
                "security_modules_count": len(security_modules),
                "module_names": module_names,
                "related_parameters_count": len(param_ids),
                "correlation_reason": "security_module_kernel_interaction"
            }
        )

    def _create_kernel_mac_correlation(
        self,
        mac_params: List[Dict[str, Any]],
        mac_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create correlation between kernel MAC parameters and MAC status."""
        param_names = [p.get("title", "") for p in mac_params]
        mac_status = [f.get("title", "") for f in mac_findings]

        return self._create_correlation_finding(
            title="Kernel MAC parameters with disabled MAC system",
            description=f"Kernel parameters related to MAC security detected but MAC system is disabled: {', '.join(mac_status)}",
            severity="high",
            risk_score=80,
            related_findings=[p["id"] for p in mac_params] + [f["id"] for f in mac_findings],
            correlation_type="kernel_mac_disabled",
            metadata={
                "mac_parameters_count": len(mac_params),
                "parameter_names": param_names,
                "mac_status": mac_status,
                "correlation_reason": "mac_parameters_without_mac_system"
            }
        )

    def _create_kernel_process_correlation(
        self,
        process_params: List[Dict[str, Any]],
        suspicious_processes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create correlation between kernel process parameters and suspicious processes."""
        param_names = [p.get("title", "") for p in process_params]
        process_names = [p.get("metadata", {}).get("command", "").split("/")[-1] for p in suspicious_processes]

        return self._create_correlation_finding(
            title="Kernel process controls with suspicious activity",
            description=f"Kernel parameters controlling process execution detected alongside suspicious processes: {', '.join(process_names[:2])}",
            severity="medium",
            risk_score=65,
            related_findings=[p["id"] for p in process_params] + [p["id"] for p in suspicious_processes],
            correlation_type="kernel_process_suspicious",
            metadata={
                "process_parameters_count": len(process_params),
                "parameter_names": param_names,
                "suspicious_processes_count": len(suspicious_processes),
                "process_names": process_names,
                "correlation_reason": "kernel_process_controls_suspicious_activity"
            }
        )
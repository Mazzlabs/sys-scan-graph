"""
Kernel modules producer for generating synthetic kernel module-related findings.
"""

from typing import Dict, List, Any
import random
import uuid
from base_producer import BaseProducer

class ModulesProducer(BaseProducer):
    """Producer for synthetic kernel modules scanner findings."""

    def __init__(self):
        super().__init__("modules")

    def _generate_normal_module(self) -> Dict[str, Any]:
        """Generate a normal kernel module finding."""
        normal_modules = [
            "i915", "nvme", "xhci_pci", "snd_hda_intel", "iwlwifi",
            "btusb", "usb_storage", "ahci", "sd_mod", "ext4",
            "btrfs", "xfs", "vfat", "nls_utf8", "crc32c_generic",
            "aesni_intel", "cryptd", "ghash_clmulni_intel", "zram",
            "coretemp", "kvm_intel", "kvm", "vfio", "vfio_pci"
        ]

        module_name = random.choice(normal_modules)

        return {
            "id": f"module_{module_name}_{uuid.uuid4().hex[:8]}",
            "title": f"Module {module_name}",
            "severity": "info",
            "risk_score": 10,
            "base_severity_score": 10,
            "description": "Loaded kernel module",
            "metadata": {},
            "operational_error": False,
            "category": "modules",
            "tags": ["kernel", "module", "normal"],
            "risk_subscores": {
                "impact": random.uniform(0.01, 0.05),
                "exposure": random.uniform(0.01, 0.03),
                "anomaly": random.uniform(0.05, 0.15),
                "confidence": random.uniform(0.9, 0.98)
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

    def _generate_suspicious_module(self) -> Dict[str, Any]:
        """Generate a suspicious kernel module finding."""
        suspicious_modules = [
            "bluetooth", "rfcomm", "bnep", "hidp", "sco",
            "rfkill", "cfg80211", "mac80211", "iwlmvm", "wl",
            "rt2800usb", "rt2x00usb", "carl9170", "ath9k", "ath5k",
            "firewire_core", "firewire_ohci", "firewire_sbp2", "dv1394",
            "raw1394", "video1394", "ohci1394", "sbp2", "eth1394"
        ]

        module_name = random.choice(suspicious_modules)

        return {
            "id": f"module_{module_name}_{uuid.uuid4().hex[:8]}",
            "title": f"Module {module_name}",
            "severity": "low",
            "risk_score": 25,
            "base_severity_score": 25,
            "description": "Potentially unnecessary kernel module loaded",
            "metadata": {},
            "operational_error": False,
            "category": "modules",
            "tags": ["kernel", "module", "suspicious", "unnecessary"],
            "risk_subscores": {
                "impact": random.uniform(0.1, 0.2),
                "exposure": random.uniform(0.05, 0.15),
                "anomaly": random.uniform(0.2, 0.4),
                "confidence": random.uniform(0.7, 0.85)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.05, 0.15),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 25,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_malicious_module(self) -> Dict[str, Any]:
        """Generate a malicious kernel module finding."""
        malicious_modules = [
            "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus",
            "squashfs", "udf", "vfat", "usb_storage", "firewire_core",
            "sctp", "rds", "tipc", "dccp", "usb_8dev", "can_dev",
            "can_raw", "can_bcm", "veth", "macvlan", "ipvlan"
        ]

        module_name = random.choice(malicious_modules)

        return {
            "id": f"module_{module_name}_{uuid.uuid4().hex[:8]}",
            "title": f"Module {module_name}",
            "severity": "high",
            "risk_score": 70,
            "base_severity_score": 70,
            "description": "Potentially vulnerable or attack surface kernel module",
            "metadata": {},
            "operational_error": False,
            "category": "modules",
            "tags": ["kernel", "module", "vulnerable", "attack_surface"],
            "risk_subscores": {
                "impact": random.uniform(0.5, 0.8),
                "exposure": random.uniform(0.3, 0.6),
                "anomaly": random.uniform(0.6, 0.9),
                "confidence": random.uniform(0.75, 0.9)
            },
            "correlation_refs": [],
            "baseline_status": "existing",
            "severity_source": "raw",
            "allowlist_reason": None,
            "probability_actionable": random.uniform(0.3, 0.6),
            "graph_degree": None,
            "cluster_id": None,
            "rationale": None,
            "risk_total": 70,
            "host_role": None,
            "host_role_rationale": None,
            "metric_drift": None
        }

    def _generate_edge_case_module(self) -> Dict[str, Any]:
        """Generate an edge case kernel module finding."""
        edge_modules = [
            "msr", "cpuid", "kvm", "kvm_intel", "kvm_amd",
            "vfio", "vfio_pci", "vfio_iommu_type1", "vfio_virqfd",
            "uio", "uio_pci_generic", "igb_uio", "rte_kni",
            "dpdk", "xdp", "bpf", "ebpf", "trace", "kprobes"
        ]

        module_name = random.choice(edge_modules)

        return {
            "id": f"module_{module_name}_{uuid.uuid4().hex[:8]}",
            "title": f"Module {module_name}",
            "severity": "medium",
            "risk_score": 45,
            "base_severity_score": 45,
            "description": "Debugging or development kernel module loaded",
            "metadata": {},
            "operational_error": False,
            "category": "modules",
            "tags": ["kernel", "module", "debug", "development"],
            "risk_subscores": {
                "impact": random.uniform(0.2, 0.4),
                "exposure": random.uniform(0.3, 0.5),
                "anomaly": random.uniform(0.7, 0.9),
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
        """Generate the specified number of kernel module findings."""
        findings = []

        for _ in range(count):
            scenario = self._choose_scenario()

            if scenario == "normal":
                finding = self._generate_normal_module()
            elif scenario == "suspicious":
                finding = self._generate_suspicious_module()
            elif scenario == "malicious":
                finding = self._generate_malicious_module()
            elif scenario == "edge_case":
                finding = self._generate_edge_case_module()

            findings.append(finding)

        return findings
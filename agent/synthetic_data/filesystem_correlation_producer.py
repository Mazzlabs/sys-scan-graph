"""
File-System correlation producer for analyzing relationships between file permissions and other findings.
"""

from typing import Dict, List, Any
import random
from base_correlation_producer import BaseCorrelationProducer

class FileSystemCorrelationProducer(BaseCorrelationProducer):
    """Analyzes correlations between file system findings and other scanner results."""

    def __init__(self):
        super().__init__("filesystem")

    def analyze_correlations(self, findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Analyze correlations between file system and other findings."""
        correlations = []

        world_writable = findings.get("world_writable", [])
        suid_findings = findings.get("suid", [])
        ioc_findings = findings.get("ioc", [])
        mac_findings = findings.get("mac", [])

        # Analyze SUID binaries in world-writable locations
        if world_writable and suid_findings:
            suid_world_writable = self._analyze_suid_world_writable(world_writable, suid_findings)
            correlations.extend(suid_world_writable)

        # Analyze file capabilities with MAC status
        if world_writable and mac_findings:
            capabilities_mac = self._analyze_capabilities_mac(world_writable, mac_findings)
            correlations.extend(capabilities_mac)

        # Analyze IOC findings with file permissions
        if ioc_findings and (world_writable or suid_findings):
            ioc_file_permissions = self._analyze_ioc_file_permissions(
                ioc_findings, world_writable + suid_findings
            )
            correlations.extend(ioc_file_permissions)

        return correlations

    def _analyze_suid_world_writable(
        self,
        world_writable: List[Dict[str, Any]],
        suid_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze SUID binaries in world-writable locations."""
        correlations = []

        # Look for high-risk combinations
        for ww_finding in world_writable:
            if ww_finding.get("severity") in ["high", "critical"]:
                # Check if there are SUID findings that might be related
                related_suid = self._find_related_suid(suid_findings, ww_finding)

                if related_suid:
                    correlation = self._create_suid_world_writable_correlation(
                        ww_finding, related_suid
                    )
                    correlations.append(correlation)

        return correlations

    def _analyze_capabilities_mac(
        self,
        world_writable: List[Dict[str, Any]],
        mac_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze file capabilities with MAC system status."""
        correlations = []

        # Look for files with capabilities when MAC is disabled/weak
        capability_files = [
            f for f in world_writable
            if "capability" in f.get("title", "").lower() or
               f.get("metadata", {}).get("rule") == "file_capability"
        ]

        if capability_files:
            # Check MAC status
            mac_disabled = any(
                f.get("metadata", {}).get("enabled") == "false" or
                f.get("severity") == "medium"
                for f in mac_findings
            )

            if mac_disabled:
                correlation = self._create_capabilities_mac_correlation(
                    capability_files, mac_findings
                )
                correlations.append(correlation)

        return correlations

    def _analyze_ioc_file_permissions(
        self,
        ioc_findings: List[Dict[str, Any]],
        file_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze IOC findings with file permission issues."""
        correlations = []

        for ioc in ioc_findings:
            if ioc.get("severity") in ["high", "critical"]:
                # Look for related file permission issues
                related_files = self._find_related_file_issues(file_findings, ioc)

                if related_files:
                    correlation = self._create_ioc_file_correlation(ioc, related_files)
                    correlations.append(correlation)

        return correlations

    def _find_related_suid(self, suid_findings: List[Dict[str, Any]], ww_finding: Dict[str, Any]) -> List[str]:
        """Find SUID findings that might be related to world-writable locations."""
        related_ids = []

        # Simple heuristic: if both are high severity, consider them related
        for suid in suid_findings:
            if suid.get("severity") in ["medium", "high", "critical"]:
                related_ids.append(suid["id"])

        return related_ids[:2]  # Limit to avoid too many correlations

    def _find_related_file_issues(self, file_findings: List[Dict[str, Any]], ioc: Dict[str, Any]) -> List[str]:
        """Find file permission issues related to IOC findings."""
        related_ids = []

        for file_finding in file_findings:
            if file_finding.get("severity") in ["medium", "high", "critical"]:
                related_ids.append(file_finding["id"])

        return related_ids[:3]

    def _create_suid_world_writable_correlation(
        self,
        ww_finding: Dict[str, Any],
        suid_ids: List[str]
    ) -> Dict[str, Any]:
        """Create correlation for SUID binary in world-writable location."""
        return self._create_correlation_finding(
            title="SUID binary in world-writable location",
            description="Privileged SUID binary found in world-writable directory, potential privilege escalation risk",
            severity="critical",
            risk_score=90,
            related_findings=[ww_finding["id"]] + suid_ids,
            correlation_type="suid_world_writable",
            metadata={
                "world_writable_location": ww_finding.get("title", ""),
                "suid_binaries_count": len(suid_ids),
                "correlation_reason": "privilege_escalation_risk"
            }
        )

    def _create_capabilities_mac_correlation(
        self,
        capability_files: List[Dict[str, Any]],
        mac_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create correlation for file capabilities with weak MAC."""
        mac_titles = [f.get("title", "") for f in mac_findings]

        return self._create_correlation_finding(
            title="File capabilities with weak MAC protection",
            description=f"Files with capabilities detected but MAC system shows weak protection: {', '.join(mac_titles)}",
            severity="high",
            risk_score=80,
            related_findings=[f["id"] for f in capability_files] + [f["id"] for f in mac_findings],
            correlation_type="capabilities_weak_mac",
            metadata={
                "capability_files_count": len(capability_files),
                "mac_status": mac_titles,
                "correlation_reason": "insufficient_mac_protection"
            }
        )

    def _create_ioc_file_correlation(
        self,
        ioc: Dict[str, Any],
        file_ids: List[str]
    ) -> Dict[str, Any]:
        """Create correlation for IOC with file permission issues."""
        ioc_title = ioc.get("title", "")

        return self._create_correlation_finding(
            title=f"IOC with file permission vulnerabilities: {ioc_title}",
            description=f"Indicator of compromise '{ioc_title}' detected alongside file permission issues",
            severity="high",
            risk_score=85,
            related_findings=[ioc["id"]] + file_ids,
            correlation_type="ioc_file_permissions",
            metadata={
                "ioc_type": ioc_title,
                "file_issues_count": len(file_ids),
                "correlation_reason": "compromise_indicators_with_permissions"
            }
        )
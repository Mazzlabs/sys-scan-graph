"""
Advanced verification agent for comprehensive data quality assessment.
"""

from typing import Dict, List, Any, Optional, Tuple
import json
import statistics
from datetime import datetime
import re

class AdvancedVerificationAgent:
    """Advanced verification agent with multi-stage validation and quality assessment."""

    def __init__(self):
        self.verification_stages = [
            "schema_validation",
            "consistency_check",
            "realism_assessment",
            "correlation_validation",
            "quality_scoring"
        ]

    def verify_dataset(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive verification of the dataset.

        Args:
            findings: Dictionary of scanner findings
            correlations: List of correlation findings

        Returns:
            Comprehensive verification report
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "pending",
            "stages": {},
            "summary": {},
            "recommendations": []
        }

        # Run all verification stages
        for stage in self.verification_stages:
            try:
                stage_result = getattr(self, f"_verify_{stage}")(findings, correlations or [])
                report["stages"][stage] = stage_result
            except Exception as e:
                report["stages"][stage] = {
                    "status": "error",
                    "error": str(e),
                    "passed": False
                }

        # Calculate overall status
        report["overall_status"] = self._calculate_overall_status(report["stages"])

        # Generate summary and recommendations
        report["summary"] = self._generate_summary(findings, correlations or [], report["stages"])
        report["recommendations"] = self._generate_recommendations(report["stages"])

        return report

    def _verify_schema_validation(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate that all findings conform to the expected schema."""
        required_fields = [
            "id", "title", "severity", "risk_score", "description",
            "metadata", "category", "tags", "risk_subscores"
        ]

        total_findings = 0
        valid_findings = 0
        invalid_findings = []

        # Check regular findings
        for scanner_type, scanner_findings in findings.items():
            for finding in scanner_findings:
                total_findings += 1
                missing_fields = [field for field in required_fields if field not in finding]

                if missing_fields:
                    invalid_findings.append({
                        "id": finding.get("id", "unknown"),
                        "scanner": scanner_type,
                        "missing_fields": missing_fields
                    })
                else:
                    valid_findings += 1

        # Check correlation findings
        for correlation in correlations:
            total_findings += 1
            correlation_fields = required_fields + ["correlation_refs", "correlation_type"]
            missing_fields = [field for field in correlation_fields if field not in correlation]

            if missing_fields:
                invalid_findings.append({
                    "id": correlation.get("id", "unknown"),
                    "scanner": "correlation",
                    "missing_fields": missing_fields
                })
            else:
                valid_findings += 1

        return {
            "status": "passed" if len(invalid_findings) == 0 else "failed",
            "passed": len(invalid_findings) == 0,
            "total_findings": total_findings,
            "valid_findings": valid_findings,
            "invalid_findings": len(invalid_findings),
            "invalid_details": invalid_findings[:10]  # Limit details
        }

    def _verify_consistency_check(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check for logical consistency across findings."""
        issues = []

        # Check for duplicate IDs
        all_ids = set()
        duplicates = []

        for scanner_type, scanner_findings in findings.items():
            for finding in scanner_findings:
                finding_id = finding.get("id")
                if finding_id in all_ids:
                    duplicates.append(finding_id)
                else:
                    all_ids.add(finding_id)

        for correlation in correlations:
            correlation_id = correlation.get("id")
            if correlation_id in all_ids:
                duplicates.append(correlation_id)
            else:
                all_ids.add(correlation_id)

        if duplicates:
            issues.append(f"Duplicate IDs found: {duplicates}")

        # Check severity and risk score consistency
        severity_risk_inconsistencies = []

        severity_mapping = {
            "info": (0, 20),
            "low": (21, 40),
            "medium": (41, 60),
            "high": (61, 80),
            "critical": (81, 100)
        }

        for scanner_type, scanner_findings in findings.items():
            for finding in scanner_findings:
                severity = finding.get("severity")
                risk_score = finding.get("risk_score", 0)

                if severity in severity_mapping:
                    min_score, max_score = severity_mapping[severity]
                    if not (min_score <= risk_score <= max_score):
                        severity_risk_inconsistencies.append({
                            "id": finding.get("id"),
                            "severity": severity,
                            "risk_score": risk_score,
                            "expected_range": f"{min_score}-{max_score}"
                        })

        if severity_risk_inconsistencies:
            issues.append(f"Severity-risk score inconsistencies: {len(severity_risk_inconsistencies)}")

        # Check correlation references exist
        broken_correlations = []
        all_finding_ids = {f.get("id") for findings_list in findings.values() for f in findings_list}
        all_finding_ids.update({c.get("id") for c in correlations})

        for correlation in correlations:
            refs = correlation.get("correlation_refs", [])
            for ref in refs:
                if ref not in all_finding_ids:
                    broken_correlations.append({
                        "correlation_id": correlation.get("id"),
                        "broken_ref": ref
                    })

        if broken_correlations:
            issues.append(f"Broken correlation references: {len(broken_correlations)}")

        return {
            "status": "passed" if len(issues) == 0 else "warning" if len(issues) <= 2 else "failed",
            "passed": len(issues) == 0,
            "issues_found": len(issues),
            "issues": issues,
            "duplicate_ids": len(duplicates),
            "severity_inconsistencies": len(severity_risk_inconsistencies),
            "broken_correlations": len(broken_correlations)
        }

    def _verify_realism_assessment(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assess the realism of the generated data."""
        assessment = {
            "status": "passed",
            "passed": True,
            "realism_score": 0.0,
            "issues": []
        }

        # Calculate scenario distribution
        total_findings = sum(len(f) for f in findings.values())
        if total_findings == 0:
            assessment["issues"].append("No findings generated")
            assessment["status"] = "failed"
            assessment["passed"] = False
            return assessment

        # Check severity distribution (should follow realistic patterns)
        severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

        for scanner_findings in findings.values():
            for finding in scanner_findings:
                severity = finding.get("severity", "unknown")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Expected realistic distribution (rough percentages)
        expected_distribution = {
            "info": 0.4,    # 40% normal/info findings
            "low": 0.3,     # 30% low severity
            "medium": 0.2,  # 20% medium severity
            "high": 0.08,   # 8% high severity
            "critical": 0.02 # 2% critical findings
        }

        realism_score = 0.0
        distribution_issues = []

        for severity, expected_pct in expected_distribution.items():
            actual_count = severity_counts[severity]
            actual_pct = actual_count / total_findings

            # Calculate deviation from expected
            deviation = abs(actual_pct - expected_pct)
            if deviation > 0.15:  # More than 15% deviation
                distribution_issues.append(
                    f"{severity}: expected {expected_pct:.1%}, got {actual_pct:.1%} (deviation: {deviation:.1%})"
                )

            # Penalize unrealistic distributions
            realism_score += (1.0 - min(deviation * 2, 1.0))

        realism_score /= len(expected_distribution)

        if distribution_issues:
            assessment["issues"].extend(distribution_issues)

        # Check for unrealistic patterns
        if severity_counts["critical"] > total_findings * 0.1:  # More than 10% critical
            assessment["issues"].append("Unrealistically high number of critical findings")
            realism_score *= 0.8

        if severity_counts["info"] < total_findings * 0.2:  # Less than 20% info
            assessment["issues"].append("Unrealistically low number of informational findings")
            realism_score *= 0.9

        assessment["realism_score"] = realism_score

        if realism_score < 0.7:
            assessment["status"] = "warning"
        if realism_score < 0.5:
            assessment["status"] = "failed"
            assessment["passed"] = False

        return assessment

    def _verify_correlation_validation(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate correlation findings and their relationships."""
        validation = {
            "status": "passed",
            "passed": True,
            "correlation_quality_score": 0.0,
            "issues": []
        }

        if not correlations:
            validation["issues"].append("No correlations generated")
            return validation

        # Check correlation quality
        quality_scores = []

        for correlation in correlations:
            score = self._assess_correlation_quality(correlation, findings)
            quality_scores.append(score)

        if quality_scores:
            avg_quality = statistics.mean(quality_scores)
            validation["correlation_quality_score"] = avg_quality

            if avg_quality < 0.6:
                validation["status"] = "warning"
                validation["issues"].append(f"Low correlation quality score: {avg_quality:.2f}")
            if avg_quality < 0.4:
                validation["status"] = "failed"
                validation["passed"] = False

        # Check for correlation redundancy
        correlation_signatures = set()
        redundant_count = 0

        for correlation in correlations:
            # Create a signature based on related findings
            refs = tuple(sorted(correlation.get("correlation_refs", [])))
            corr_type = correlation.get("correlation_type", "")

            signature = (refs, corr_type)
            if signature in correlation_signatures:
                redundant_count += 1
            else:
                correlation_signatures.add(signature)

        if redundant_count > 0:
            validation["issues"].append(f"Redundant correlations found: {redundant_count}")

        return validation

    def _assess_correlation_quality(
        self,
        correlation: Dict[str, Any],
        findings: Dict[str, List[Dict[str, Any]]]
    ) -> float:
        """Assess the quality of a single correlation."""
        score = 1.0

        # Check if correlation references exist
        refs = correlation.get("correlation_refs", [])
        if not refs:
            return 0.0

        # Find referenced findings
        found_refs = 0
        total_refs = len(refs)

        all_findings = {}
        for scanner_findings in findings.values():
            for finding in scanner_findings:
                all_findings[finding.get("id")] = finding

        for ref in refs:
            if ref in all_findings:
                found_refs += 1

        if found_refs < total_refs:
            score *= 0.8  # Penalty for broken references

        # Assess correlation strength based on finding severities
        severity_score = 0.0
        for ref in refs:
            if ref in all_findings:
                severity = all_findings[ref].get("severity", "info")
                severity_weights = {
                    "info": 0.1, "low": 0.3, "medium": 0.6,
                    "high": 0.8, "critical": 1.0
                }
                severity_score += severity_weights.get(severity, 0.1)

        severity_score /= len(refs)
        score *= (0.5 + severity_score * 0.5)  # Blend with base score

        return min(score, 1.0)

    def _verify_quality_scoring(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Perform overall quality scoring of the dataset."""
        quality_metrics = {
            "diversity_score": self._calculate_diversity_score(findings),
            "completeness_score": self._calculate_completeness_score(findings),
            "consistency_score": self._calculate_consistency_score(findings),
            "correlation_coverage": self._calculate_correlation_coverage(findings, correlations)
        }

        overall_quality = statistics.mean(quality_metrics.values())

        return {
            "status": "passed" if overall_quality >= 0.7 else "warning" if overall_quality >= 0.5 else "failed",
            "passed": overall_quality >= 0.7,
            "overall_quality_score": overall_quality,
            "quality_metrics": quality_metrics
        }

    def _calculate_diversity_score(self, findings: Dict[str, List[Dict[str, Any]]]) -> float:
        """Calculate diversity score based on variety of findings."""
        if not findings:
            return 0.0

        # Check scanner type diversity
        scanner_count = len(findings)
        diversity = min(scanner_count / 8, 1.0)  # Normalize to 8 expected scanners

        # Check finding type diversity within scanners
        type_diversity = 0.0
        for scanner_findings in findings.values():
            if scanner_findings:
                unique_titles = len(set(f.get("title", "") for f in scanner_findings))
                type_diversity += min(unique_titles / len(scanner_findings), 1.0)

        type_diversity /= len(findings)

        return (diversity + type_diversity) / 2

    def _calculate_completeness_score(self, findings: Dict[str, List[Dict[str, Any]]]) -> float:
        """Calculate completeness score based on expected data fields."""
        if not findings:
            return 0.0

        total_findings = sum(len(f) for f in findings.values())
        complete_findings = 0

        required_fields = ["id", "title", "severity", "risk_score", "description", "metadata"]

        for scanner_findings in findings.values():
            for finding in scanner_findings:
                if all(field in finding for field in required_fields):
                    complete_findings += 1

        return complete_findings / total_findings if total_findings > 0 else 0.0

    def _calculate_consistency_score(self, findings: Dict[str, List[Dict[str, Any]]]) -> float:
        """Calculate consistency score based on data patterns."""
        if not findings:
            return 0.0

        # Check risk score ranges consistency
        risk_scores = []
        for scanner_findings in findings.values():
            for finding in scanner_findings:
                risk_score = finding.get("risk_score")
                if isinstance(risk_score, (int, float)) and 0 <= risk_score <= 100:
                    risk_scores.append(risk_score)

        if not risk_scores:
            return 0.0

        # Check if risk scores follow reasonable distribution
        mean_score = statistics.mean(risk_scores)
        std_dev = statistics.stdev(risk_scores) if len(risk_scores) > 1 else 0

        # Penalize if too concentrated or too spread out
        concentration_penalty = abs(mean_score - 50) / 50  # Distance from middle
        spread_penalty = min(abs(std_dev - 20) / 20, 1.0)  # Deviation from expected spread

        return max(0.0, 1.0 - (concentration_penalty + spread_penalty) / 2)

    def _calculate_correlation_coverage(self, findings: Dict[str, List[Dict[str, Any]]], correlations: List[Dict[str, Any]]) -> float:
        """Calculate correlation coverage score."""
        total_findings = sum(len(f) for f in findings.values())

        if total_findings == 0:
            return 0.0

        # Count how many findings are involved in correlations
        correlated_finding_ids = set()

        for correlation in correlations:
            refs = correlation.get("correlation_refs", [])
            correlated_finding_ids.update(refs)

        coverage = len(correlated_finding_ids) / total_findings
        return min(coverage, 1.0)  # Cap at 100%

    def _calculate_overall_status(self, stages: Dict[str, Any]) -> str:
        """Calculate overall verification status."""
        failed_stages = sum(1 for stage in stages.values() if stage.get("status") == "failed")
        warning_stages = sum(1 for stage in stages.values() if stage.get("status") == "warning")

        if failed_stages > 0:
            return "failed"
        elif warning_stages > len(stages) / 2:
            return "warning"
        else:
            return "passed"

    def _generate_summary(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]],
        stages: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a summary of verification results."""
        total_findings = sum(len(f) for f in findings.values())

        return {
            "total_findings": total_findings,
            "total_correlations": len(correlations),
            "scanner_coverage": len(findings),
            "stages_passed": sum(1 for stage in stages.values() if stage.get("passed", False)),
            "stages_failed": sum(1 for stage in stages.values() if stage.get("status") == "failed"),
            "stages_warning": sum(1 for stage in stages.values() if stage.get("status") == "warning")
        }

    def _generate_recommendations(self, stages: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on verification results."""
        recommendations = []

        # Schema validation recommendations
        schema_stage = stages.get("schema_validation", {})
        if not schema_stage.get("passed", False):
            invalid_count = schema_stage.get("invalid_findings", 0)
            recommendations.append(f"Fix schema validation issues in {invalid_count} findings")

        # Consistency recommendations
        consistency_stage = stages.get("consistency_check", {})
        if not consistency_stage.get("passed", False):
            issues = consistency_stage.get("issues", [])
            if issues:
                recommendations.append("Address consistency issues: " + "; ".join(issues[:2]))

        # Realism recommendations
        realism_stage = stages.get("realism_assessment", {})
        realism_score = realism_stage.get("realism_score", 1.0)
        if realism_score < 0.8:
            recommendations.append(".2f")

        # Correlation recommendations
        correlation_stage = stages.get("correlation_validation", {})
        if not correlation_stage.get("passed", False):
            quality_score = correlation_stage.get("correlation_quality_score", 0.0)
            if quality_score < 0.6:
                recommendations.append(".2f")

        # Quality recommendations
        quality_stage = stages.get("quality_scoring", {})
        if not quality_stage.get("passed", False):
            quality_score = quality_stage.get("overall_quality_score", 0.0)
            if quality_score < 0.7:
                recommendations.append(".2f")

        if not recommendations:
            recommendations.append("Dataset quality is good - no major issues found")

        return recommendations
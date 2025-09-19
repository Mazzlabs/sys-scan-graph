"""
Data transformation pipeline for optimizing and enriching synthetic datasets.
"""

from typing import Dict, List, Any, Optional, Union
import json
import gzip
import hashlib
from datetime import datetime
from pathlib import Path
import statistics
from collections import defaultdict

try:
    from langchain_core.documents import Document
    from langchain_core.prompts import PromptTemplate
    from langchain_core.output_parsers import JsonOutputParser
    from langchain_core.runnables import RunnablePassthrough
    from langchain_openai import ChatOpenAI
    LANGCHAIN_AVAILABLE = True
except ImportError:
    # Handle case where langchain packages are not available
    LANGCHAIN_AVAILABLE = False
    print("Warning: LangChain not available. Advanced data enrichment features will be limited.")

class DataTransformationPipeline:
    """Pipeline for transforming and optimizing synthetic security data."""

    def __init__(self, use_langchain: bool = True):
        self.use_langchain = use_langchain and LANGCHAIN_AVAILABLE
        if self.use_langchain:
            self._setup_langchain_components()
        else:
            print("Using basic transformation without LangChain enrichment")

    def _setup_langchain_components(self):
        """Set up LangChain components for data enrichment."""
        if not LANGCHAIN_AVAILABLE:
            return

        # Initialize LLM for data enrichment
        self.llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0.1,
            max_tokens=500
        )

        # Create enrichment prompt
        enrichment_prompt = PromptTemplate.from_template("""
        Analyze the following security finding and provide enriched metadata:

        Finding: {finding_title}
        Description: {finding_description}
        Severity: {finding_severity}
        Category: {finding_category}

        Provide a JSON response with:
        - mitigation_steps: Array of specific remediation actions
        - attack_vectors: Array of potential attack methods this finding could indicate
        - compliance_impact: Array of compliance frameworks affected
        - business_impact: Brief description of business impact
        - technical_details: Additional technical context

        Response format: JSON only
        """)

        self.enrichment_chain = (
            RunnablePassthrough()
            | enrichment_prompt
            | self.llm
            | JsonOutputParser()
        )

    def transform_dataset(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]],
        verification_report: Dict[str, Any],
        output_format: str = "optimized_json",
        compress: bool = False
    ) -> Dict[str, Any]:
        """
        Transform raw findings into optimized dataset.

        Args:
            findings: Raw scanner findings
            correlations: Correlation findings
            verification_report: Verification results
            output_format: Format for output dataset
            compress: Whether to compress the output

        Returns:
            Transformed and optimized dataset
        """
        print("Starting data transformation pipeline...")

        # Step 1: Data normalization and cleaning
        normalized_findings = self._normalize_findings(findings)
        normalized_correlations = self._normalize_correlations(correlations)

        # Step 2: Data enrichment (if LangChain available)
        if self.use_langchain:
            enriched_findings = self._enrich_findings_with_langchain(normalized_findings)
            enriched_correlations = self._enrich_correlations_with_langchain(normalized_correlations)
        else:
            enriched_findings = normalized_findings
            enriched_correlations = normalized_correlations

        # Step 3: Dataset optimization
        optimized_dataset = self._optimize_dataset_structure(
            enriched_findings,
            enriched_correlations,
            verification_report
        )

        # Step 4: Generate metadata and statistics
        dataset_metadata = self._generate_dataset_metadata(
            optimized_dataset,
            verification_report
        )

        # Step 5: Final formatting
        final_dataset: Dict[str, Any] = self._format_final_dataset(
            optimized_dataset,
            dataset_metadata,
            output_format
        )

        # Step 6: Compression (optional)
        if compress:
            final_dataset = self._compress_dataset(final_dataset)

        print("Data transformation pipeline completed")
        return final_dataset

    def _normalize_findings(self, findings: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Normalize and clean finding data."""
        normalized = {}

        for scanner_type, scanner_findings in findings.items():
            normalized[scanner_type] = []

            for finding in scanner_findings:
                # Ensure all required fields exist
                normalized_finding = self._ensure_required_fields(finding)

                # Normalize data types
                normalized_finding = self._normalize_data_types(normalized_finding)

                # Clean and standardize text fields
                normalized_finding = self._clean_text_fields(normalized_finding)

                # Add processing metadata
                normalized_finding["_processed_at"] = datetime.now().isoformat()
                normalized_finding["_data_quality"] = self._assess_finding_quality(normalized_finding)

                normalized[scanner_type].append(normalized_finding)

        return normalized

    def _normalize_correlations(self, correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize correlation data."""
        normalized = []

        for correlation in correlations:
            normalized_correlation = self._ensure_required_fields(correlation)
            normalized_correlation = self._normalize_data_types(normalized_correlation)
            normalized_correlation = self._clean_text_fields(normalized_correlation)

            # Add correlation-specific metadata
            normalized_correlation["_correlation_strength"] = correlation.get("correlation_strength", 0.5)
            normalized_correlation["_processed_at"] = datetime.now().isoformat()

            normalized.append(normalized_correlation)

        return normalized

    def _ensure_required_fields(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure all required fields are present in the item."""
        required_fields = {
            "id": f"unknown_{hash(str(item))}",
            "title": "Unknown Finding",
            "severity": "info",
            "risk_score": 10,
            "description": "No description available",
            "metadata": {},
            "category": "unknown",
            "tags": []
        }

        for field, default_value in required_fields.items():
            if field not in item or item[field] is None:
                item[field] = default_value

        return item

    def _normalize_data_types(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize data types for consistency."""
        # Ensure risk_score is numeric
        if "risk_score" in item:
            try:
                item["risk_score"] = float(item["risk_score"])
            except (ValueError, TypeError):
                item["risk_score"] = 10.0

        # Ensure risk_subscores are properly formatted
        if "risk_subscores" in item and isinstance(item["risk_subscores"], dict):
            for key in ["impact", "exposure", "anomaly", "confidence"]:
                if key in item["risk_subscores"]:
                    try:
                        item["risk_subscores"][key] = float(item["risk_subscores"][key])
                    except (ValueError, TypeError):
                        item["risk_subscores"][key] = 0.5

        # Ensure tags is a list
        if "tags" in item and not isinstance(item["tags"], list):
            item["tags"] = [str(item["tags"])]

        return item

    def _clean_text_fields(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and standardize text fields."""
        text_fields = ["title", "description"]

        for field in text_fields:
            if field in item and isinstance(item[field], str):
                # Remove extra whitespace
                item[field] = " ".join(item[field].split())
                # Ensure proper capitalization for titles
                if field == "title":
                    item[field] = item[field].strip()

        return item

    def _assess_finding_quality(self, finding: Dict[str, Any]) -> float:
        """Assess the quality score of a finding."""
        score = 1.0

        # Penalize for missing or empty fields
        if not finding.get("description") or finding["description"] == "No description available":
            score *= 0.8

        if not finding.get("metadata"):
            score *= 0.9

        # Penalize for unrealistic risk scores
        risk_score = finding.get("risk_score", 10)
        if risk_score < 0 or risk_score > 100:
            score *= 0.7

        return round(score, 2)

    def _enrich_findings_with_langchain(self, findings: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """Enrich findings using LangChain for additional context."""
        if not self.use_langchain:
            return findings

        enriched = {}

        for scanner_type, scanner_findings in findings.items():
            enriched[scanner_type] = []

            for finding in scanner_findings:
                try:
                    # Use LangChain to enrich the finding
                    enrichment_input = {
                        "finding_title": finding.get("title", ""),
                        "finding_description": finding.get("description", ""),
                        "finding_severity": finding.get("severity", ""),
                        "finding_category": finding.get("category", "")
                    }

                    enrichment_result = self.enrichment_chain.invoke(enrichment_input)

                    # Merge enrichment data
                    enriched_finding = finding.copy()
                    enriched_finding["_langchain_enrichment"] = enrichment_result
                    enriched_finding["_enrichment_timestamp"] = datetime.now().isoformat()

                    enriched[scanner_type].append(enriched_finding)

                except Exception as e:
                    print(f"Warning: Failed to enrich finding {finding.get('id')}: {e}")
                    # Add basic enrichment fallback
                    enriched_finding = finding.copy()
                    enriched_finding["_langchain_enrichment"] = {
                        "error": "Enrichment failed",
                        "fallback": True
                    }
                    enriched[scanner_type].append(enriched_finding)

        return enriched

    def _enrich_correlations_with_langchain(self, correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich correlations using LangChain."""
        if not self.use_langchain:
            return correlations

        enriched = []

        for correlation in correlations:
            try:
                # Create enrichment prompt for correlations
                enrichment_input = {
                    "correlation_title": correlation.get("title", ""),
                    "correlation_description": correlation.get("description", ""),
                    "correlation_type": correlation.get("correlation_type", ""),
                    "related_findings_count": len(correlation.get("correlation_refs", []))
                }

                # Use a simple enrichment for correlations
                enriched_correlation = correlation.copy()
                enriched_correlation["_correlation_analysis"] = {
                    "relationship_strength": correlation.get("correlation_strength", 0.5),
                    "analysis_timestamp": datetime.now().isoformat(),
                    "enriched": True
                }

                enriched.append(enriched_correlation)

            except Exception as e:
                print(f"Warning: Failed to enrich correlation {correlation.get('id')}: {e}")
                enriched.append(correlation)

        return enriched

    def _optimize_dataset_structure(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]],
        verification_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Optimize the dataset structure for efficiency."""
        # Create optimized structure
        optimized = {
            "version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "dataset_type": "synthetic_security_findings",
            "findings": {},
            "correlations": [],
            "statistics": {},
            "indexes": {}
        }

        # Optimize findings storage
        for scanner_type, scanner_findings in findings.items():
            # Group findings by severity for efficient querying
            severity_groups = defaultdict(list)

            for finding in scanner_findings:
                severity = finding.get("severity", "info")
                severity_groups[severity].append(finding)

            optimized["findings"][scanner_type] = dict(severity_groups)

        # Optimize correlations
        optimized["correlations"] = correlations

        # Add statistics
        optimized["statistics"] = self._calculate_dataset_statistics(findings, correlations)

        # Create indexes for efficient lookup
        optimized["indexes"] = self._create_dataset_indexes(findings, correlations)

        return optimized

    def _calculate_dataset_statistics(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate comprehensive dataset statistics."""
        stats = {
            "total_findings": 0,
            "total_correlations": len(correlations),
            "scanner_types": len(findings),
            "severity_distribution": defaultdict(int),
            "category_distribution": defaultdict(int),
            "risk_score_stats": {},
            "correlation_stats": {}
        }

        # Calculate finding statistics
        all_findings = []
        for scanner_findings in findings.values():
            for finding in scanner_findings:
                all_findings.append(finding)
                stats["total_findings"] += 1

                # Severity distribution
                severity = finding.get("severity", "unknown")
                stats["severity_distribution"][severity] += 1

                # Category distribution
                category = finding.get("category", "unknown")
                stats["category_distribution"][category] += 1

        # Risk score statistics
        if all_findings:
            risk_scores = [f.get("risk_score", 0) for f in all_findings]
            stats["risk_score_stats"] = {
                "mean": round(statistics.mean(risk_scores), 2),
                "median": round(statistics.median(risk_scores), 2),
                "min": min(risk_scores),
                "max": max(risk_scores),
                "std_dev": round(statistics.stdev(risk_scores), 2) if len(risk_scores) > 1 else 0
            }

        # Correlation statistics
        if correlations:
            correlation_types = [c.get("correlation_type", "unknown") for c in correlations]
            stats["correlation_stats"] = {
                "types": dict((t, correlation_types.count(t)) for t in set(correlation_types)),
                "avg_strength": round(statistics.mean([c.get("correlation_strength", 0.5) for c in correlations]), 2)
            }

        return dict(stats)

    def _create_dataset_indexes(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create indexes for efficient dataset querying."""
        indexes = {
            "findings_by_id": {},
            "findings_by_severity": defaultdict(list),
            "findings_by_category": defaultdict(list),
            "correlations_by_type": defaultdict(list),
            "correlations_by_finding": defaultdict(list)
        }

        # Index findings
        for scanner_type, scanner_findings in findings.items():
            for finding in scanner_findings:
                finding_id = finding.get("id")

                # By ID
                indexes["findings_by_id"][finding_id] = {
                    "scanner": scanner_type,
                    "severity": finding.get("severity"),
                    "category": finding.get("category")
                }

                # By severity
                severity = finding.get("severity", "unknown")
                indexes["findings_by_severity"][severity].append(finding_id)

                # By category
                category = finding.get("category", "unknown")
                indexes["findings_by_category"][category].append(finding_id)

        # Index correlations
        for correlation in correlations:
            corr_type = correlation.get("correlation_type", "unknown")
            indexes["correlations_by_type"][corr_type].append(correlation.get("id"))

            # By related findings
            for ref in correlation.get("correlation_refs", []):
                indexes["correlations_by_finding"][ref].append(correlation.get("id"))

        return dict(indexes)

    def _generate_dataset_metadata(
        self,
        optimized_dataset: Dict[str, Any],
        verification_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive metadata for the dataset."""
        metadata = {
            "dataset_id": hashlib.md5(str(datetime.now()).encode()).hexdigest()[:16],
            "creation_timestamp": datetime.now().isoformat(),
            "version": "2.0",
            "format": "optimized_json",
            "compression": False,
            "langchain_enriched": self.use_langchain,
            "verification_summary": {
                "overall_status": verification_report.get("overall_status", "unknown"),
                "stages_passed": verification_report.get("summary", {}).get("stages_passed", 0),
                "quality_score": verification_report.get("stages", {}).get("quality_scoring", {}).get("overall_quality_score", 0.0)
            },
            "data_characteristics": {
                "total_findings": optimized_dataset.get("statistics", {}).get("total_findings", 0),
                "total_correlations": optimized_dataset.get("statistics", {}).get("total_correlations", 0),
                "scanner_coverage": optimized_dataset.get("statistics", {}).get("scanner_types", 0)
            },
            "processing_pipeline": [
                "data_normalization",
                "quality_assessment",
                "langchain_enrichment" if self.use_langchain else "basic_enrichment",
                "structure_optimization",
                "indexing",
                "metadata_generation"
            ]
        }

        return metadata

    def _format_final_dataset(
        self,
        optimized_dataset: Dict[str, Any],
        metadata: Dict[str, Any],
        output_format: str
    ) -> Dict[str, Any]:
        """Format the final dataset according to the specified format."""
        if output_format == "optimized_json":
            return {
                "metadata": metadata,
                "data": optimized_dataset
            }
        elif output_format == "flat_json":
            # Flatten the structure for simpler processing
            return {
                "metadata": metadata,
                "findings": optimized_dataset.get("findings", {}),
                "correlations": optimized_dataset.get("correlations", []),
                "statistics": optimized_dataset.get("statistics", {}),
                "indexes": optimized_dataset.get("indexes", {})
            }
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def _compress_dataset(self, dataset: Dict[str, Any]) -> Dict[str, Any]:
        """Compress the dataset using gzip."""
        json_str = json.dumps(dataset, indent=None, separators=(',', ':'))
        compressed = gzip.compress(json_str.encode('utf-8'))

        # Return as dict with compression info
        return {
            "compressed": True,
            "compression_method": "gzip",
            "original_size": len(json_str),
            "compressed_size": len(compressed),
            "data": compressed.hex()  # Store as hex string for JSON compatibility
        }

    def save_dataset(
        self,
        dataset: Dict[str, Any],
        output_path: Union[str, Path],
        compress: bool = False
    ) -> str:
        """
        Save the transformed dataset to file.

        Args:
            dataset: The transformed dataset
            output_path: Path to save the dataset
            compress: Whether to compress the output

        Returns:
            Path to the saved file
        """
        output_path = Path(output_path)

        if compress and isinstance(dataset.get("data"), bytes):
            # Already compressed
            with open(output_path, 'wb') as f:
                f.write(dataset["data"])
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(dataset, f, indent=2, ensure_ascii=False)

        print(f"Dataset saved to: {output_path}")
        return str(output_path)
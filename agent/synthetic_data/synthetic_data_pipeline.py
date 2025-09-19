"""
End-to-end data pipeline for synthetic security data generation and processing.
"""

from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import json
from datetime import datetime

from producer_registry import registry
from correlation_registry import correlation_registry
from advanced_verification_agent import AdvancedVerificationAgent
from data_transformation_pipeline import DataTransformationPipeline

class SyntheticDataPipeline:
    """Complete pipeline for generating, correlating, verifying, and transforming synthetic security data."""

    def __init__(self, use_langchain: bool = True, conservative_parallel: bool = True, gpu_optimized: Optional[bool] = None):
        """
        Initialize the synthetic data pipeline.

        Args:
            use_langchain: Whether to use LangChain for data enrichment
            conservative_parallel: Whether to use conservative parallel processing
            gpu_optimized: Whether to use GPU-optimized parallel processing (auto-detect if None)
        """
        self.use_langchain = use_langchain
        self.conservative_parallel = conservative_parallel
        self.gpu_optimized = gpu_optimized

        self.producer_registry = registry
        self.correlation_registry = correlation_registry
        self.verification_agent = AdvancedVerificationAgent()
        self.transformation_pipeline = DataTransformationPipeline(use_langchain=use_langchain)

        # Pipeline execution state
        self.execution_state = {
            "stage": "initialized",
            "start_time": None,
            "end_time": None,
            "findings_generated": 0,
            "correlations_generated": 0,
            "verification_passed": False,
            "transformation_completed": False
        }

    def execute_pipeline(
        self,
        producer_counts: Optional[Dict[str, int]] = None,
        output_path: Optional[Union[str, Path]] = None,
        output_format: str = "optimized_json",
        compress: bool = False,
        save_intermediate: bool = False
    ) -> Dict[str, Any]:
        """
        Execute the complete synthetic data pipeline.

        Args:
            producer_counts: Number of findings to generate per producer
            output_path: Path to save the final dataset
            output_format: Format for the output dataset
            compress: Whether to compress the output
            save_intermediate: Whether to save intermediate results

        Returns:
            Complete pipeline execution results
        """
        self.execution_state["stage"] = "running"
        self.execution_state["start_time"] = datetime.now().isoformat()

        print("🚀 Starting Synthetic Data Pipeline Execution")
        print("=" * 60)

        try:
            # Stage 1: Generate findings from all producers
            print("\n📊 Stage 1: Generating Findings")
            findings = self._execute_finding_generation(producer_counts)
            self.execution_state["findings_generated"] = sum(len(f) for f in findings.values())

            if save_intermediate:
                self._save_intermediate("raw_findings.json", findings)

            # Stage 2: Generate correlations
            print("\n🔗 Stage 2: Analyzing Correlations")
            correlations = self._execute_correlation_analysis(findings)
            self.execution_state["correlations_generated"] = len(correlations)

            if save_intermediate:
                self._save_intermediate("correlations.json", correlations)

            # Stage 3: Verify data quality
            print("\n✅ Stage 3: Verifying Data Quality")
            verification_report = self._execute_verification(findings, correlations)
            self.execution_state["verification_passed"] = verification_report.get("overall_status") == "passed"

            if save_intermediate:
                self._save_intermediate("verification_report.json", verification_report)

            # Stage 4: Transform and optimize dataset
            print("\n🔄 Stage 4: Transforming Dataset")
            transformed_dataset = self._execute_transformation(
                findings, correlations, verification_report, output_format, compress
            )
            self.execution_state["transformation_completed"] = True

            # Stage 5: Save final dataset (if output path provided)
            if output_path:
                print("\n💾 Stage 5: Saving Dataset")
                saved_path = self._save_final_dataset(transformed_dataset, output_path, compress)
                self.execution_state["output_path"] = saved_path

            # Update execution state
            self.execution_state["stage"] = "completed"
            self.execution_state["end_time"] = datetime.now().isoformat()

            # Generate final report
            final_report = self._generate_pipeline_report(
                findings, correlations, verification_report, transformed_dataset
            )

            print("\n🎉 Pipeline Execution Completed Successfully!")
            print(f"📈 Generated {self.execution_state['findings_generated']} findings")
            print(f"🔗 Generated {self.execution_state['correlations_generated']} correlations")
            print(f"✅ Verification: {verification_report.get('overall_status', 'unknown').upper()}")

            return final_report

        except Exception as e:
            self.execution_state["stage"] = "failed"
            self.execution_state["error"] = str(e)
            self.execution_state["end_time"] = datetime.now().isoformat()

            print(f"\n❌ Pipeline Execution Failed: {e}")
            raise

    def _execute_finding_generation(self, producer_counts: Optional[Dict[str, int]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Execute finding generation from all producers."""
        print(f"  Generating findings from {len(self.producer_registry.list_producers())} producers...")

        if producer_counts is None:
            # Default: 10 findings per producer
            producer_counts = {name: 10 for name in self.producer_registry.list_producers()}

        findings = self.producer_registry.generate_all_findings(producer_counts, self.conservative_parallel, self.gpu_optimized)

        total_findings = sum(len(f) for f in findings.values())
        print(f"  ✓ Generated {total_findings} total findings")

        return findings

    def _execute_correlation_analysis(self, findings: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Execute correlation analysis across all findings."""
        print(f"  Analyzing correlations with {len(self.correlation_registry.list_correlation_producers())} correlation producers...")

        correlations = self.correlation_registry.analyze_all_correlations(findings, self.conservative_parallel, self.gpu_optimized)

        # Get correlation summary
        summary = self.correlation_registry.get_correlation_summary(correlations)
        print(f"  ✓ Generated {len(correlations)} correlations")
        print(f"    Top correlation types: {list(summary.get('correlation_types', {}).keys())[:3]}")

        return correlations

    def _execute_verification(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Execute comprehensive data verification."""
        print("  Running multi-stage verification...")

        verification_report = self.verification_agent.verify_dataset(findings, correlations)

        status = verification_report.get("overall_status", "unknown")
        stages_passed = verification_report.get("summary", {}).get("stages_passed", 0)
        total_stages = len(verification_report.get("stages", {}))

        print(f"  ✓ Verification completed: {status.upper()}")
        print(f"    Stages passed: {stages_passed}/{total_stages}")

        return verification_report

    def _execute_transformation(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]],
        verification_report: Dict[str, Any],
        output_format: str,
        compress: bool
    ) -> Dict[str, Any]:
        """Execute data transformation and optimization."""
        print(f"  Transforming dataset (format: {output_format}, compress: {compress})...")

        transformed_dataset = self.transformation_pipeline.transform_dataset(
            findings=findings,
            correlations=correlations,
            verification_report=verification_report,
            output_format=output_format,
            compress=compress
        )

        print("  ✓ Dataset transformation completed")

        return transformed_dataset

    def _save_final_dataset(
        self,
        dataset: Dict[str, Any],
        output_path: Union[str, Path],
        compress: bool
    ) -> str:
        """Save the final transformed dataset."""
        saved_path = self.transformation_pipeline.save_dataset(
            dataset, output_path, compress
        )

        print(f"  ✓ Dataset saved to: {saved_path}")

        return saved_path

    def _save_intermediate(self, filename: str, data: Any):
        """Save intermediate results for debugging/analysis."""
        intermediate_dir = Path("intermediate_results")
        intermediate_dir.mkdir(exist_ok=True)

        output_path = intermediate_dir / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        print(f"  💾 Intermediate result saved: {output_path}")

    def _generate_pipeline_report(
        self,
        findings: Dict[str, List[Dict[str, Any]]],
        correlations: List[Dict[str, Any]],
        verification_report: Dict[str, Any],
        transformed_dataset: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a comprehensive pipeline execution report."""
        report = {
            "pipeline_execution": self.execution_state.copy(),
            "data_summary": {
                "total_findings": sum(len(f) for f in findings.values()),
                "total_correlations": len(correlations),
                "scanner_types": len(findings),
                "correlation_types": len(set(c.get("correlation_type") for c in correlations))
            },
            "quality_metrics": {
                "verification_status": verification_report.get("overall_status"),
                "stages_passed": verification_report.get("summary", {}).get("stages_passed", 0),
                "quality_score": verification_report.get("stages", {}).get("quality_scoring", {}).get("overall_quality_score", 0.0)
            },
            "dataset_characteristics": {
                "version": transformed_dataset.get("metadata", {}).get("version", "unknown"),
                "format": transformed_dataset.get("metadata", {}).get("format", "unknown"),
                "compressed": transformed_dataset.get("metadata", {}).get("compression", False),
                "langchain_enriched": transformed_dataset.get("metadata", {}).get("langchain_enriched", False)
            },
            "performance_metrics": {
                "execution_time": self._calculate_execution_time(),
                "findings_per_second": self._calculate_findings_per_second(),
                "data_size_mb": self._estimate_dataset_size(transformed_dataset)
            },
            "recommendations": verification_report.get("recommendations", [])
        }

        return report

    def _calculate_execution_time(self) -> float:
        """Calculate total pipeline execution time in seconds."""
        if not self.execution_state.get("start_time") or not self.execution_state.get("end_time"):
            return 0.0

        start = datetime.fromisoformat(self.execution_state["start_time"])
        end = datetime.fromisoformat(self.execution_state["end_time"])

        return (end - start).total_seconds()

    def _calculate_findings_per_second(self) -> float:
        """Calculate findings generation rate."""
        execution_time = self._calculate_execution_time()
        if execution_time == 0:
            return 0.0

        return self.execution_state.get("findings_generated", 0) / execution_time

    def _estimate_dataset_size(self, dataset: Dict[str, Any]) -> float:
        """Estimate dataset size in MB."""
        try:
            json_str = json.dumps(dataset, separators=(',', ':'))
            size_bytes = len(json_str.encode('utf-8'))
            return round(size_bytes / (1024 * 1024), 2)
        except:
            return 0.0

    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline execution status."""
        return self.execution_state.copy()

    def get_available_producers(self) -> List[str]:
        """Get list of available producers."""
        return self.producer_registry.list_producers()

    def get_available_correlation_producers(self) -> List[str]:
        """Get list of available correlation producers."""
        return self.correlation_registry.list_correlation_producers()

# Convenience function for quick pipeline execution
def run_synthetic_data_pipeline(
    output_path: str = "synthetic_security_dataset.json",
    producer_counts: Optional[Dict[str, int]] = None,
    use_langchain: bool = True,
    compress: bool = False,
    conservative_parallel: bool = True,
    gpu_optimized: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Convenience function to run the complete synthetic data pipeline.

    Args:
        output_path: Path to save the final dataset
        producer_counts: Number of findings per producer (default: 10 each)
        use_langchain: Whether to use LangChain for enrichment
        compress: Whether to compress the output
        conservative_parallel: Whether to use conservative parallel processing
        gpu_optimized: Whether to use GPU-optimized parallel processing (auto-detect if None)

    Returns:
        Pipeline execution report
    """
    pipeline = SyntheticDataPipeline(
        use_langchain=use_langchain,
        conservative_parallel=conservative_parallel,
        gpu_optimized=gpu_optimized
    )

    return pipeline.execute_pipeline(
        producer_counts=producer_counts,
        output_path=output_path,
        compress=compress,
        save_intermediate=True
    )

if __name__ == "__main__":
    # Example usage
    print("Running synthetic data pipeline...")

    result = run_synthetic_data_pipeline(
        output_path="synthetic_dataset_example.json",
        producer_counts={"processes": 5, "network": 5, "kernel_params": 3},
        use_langchain=False,  # Set to True if LangChain is available
        compress=False
    )

    print("\nPipeline completed!")
    print(f"Generated {result['data_summary']['total_findings']} findings")
    print(f"Generated {result['data_summary']['total_correlations']} correlations")
    print(f"Quality score: {result['quality_metrics']['quality_score']:.2f}")
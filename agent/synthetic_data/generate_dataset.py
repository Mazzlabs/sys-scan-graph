#!/usr/bin/env python3
"""
Production-ready synthetic data generation pipeline for massive dataset creation.
Optimized for T4 GPU with extended runtime capabilities.
"""

import argparse
import sys
import os
import json
import time
import signal
from pathlib import Path
from typing import Dict, Any, Optional
import threading

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

# Add the synthetic_data directory to the path
script_dir = os.path.dirname(os.path.abspath(__file__) if '__file__' in globals() else os.getcwd())
sys.path.insert(0, script_dir)

from synthetic_data_pipeline import SyntheticDataPipeline

class DatasetGenerator:
    """Production dataset generator with monitoring and extended runtime support."""

    def __init__(self, gpu_optimized: bool = True, conservative_parallel: bool = False):
        self.gpu_optimized = gpu_optimized
        self.conservative_parallel = conservative_parallel
        self.pipeline = SyntheticDataPipeline(
            use_langchain=False,
            conservative_parallel=conservative_parallel,
            gpu_optimized=gpu_optimized
        )
        self.running = True
        self.stats = {
            "start_time": None,
            "end_time": None,
            "batches_completed": 0,
            "total_findings": 0,
            "total_correlations": 0,
            "errors": []
        }

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n⚠️  Received signal {signum}, shutting down gracefully...")
        self.running = False

    def _monitor_resources(self):
        """Monitor system resources during generation."""
        if not HAS_PSUTIL or psutil is None:
            return

        while self.running:
            try:
                cpu_percent = psutil.cpu_percent(interval=5)
                memory = psutil.virtual_memory()
                print(f"📊 CPU: {cpu_percent:.1f}% | Memory: {memory.percent:.1f}% | Findings: {self.stats['total_findings']:,}")
                time.sleep(30)  # Update every 30 seconds
            except:
                break

    def generate_massive_dataset(
        self,
        output_dir: str,
        batch_size: int = 5000,
        max_batches: int = 10,
        max_runtime_hours: float = 2.0
    ) -> Dict[str, Any]:
        """
        Generate massive dataset through multiple batches.

        Args:
            output_dir: Output directory
            batch_size: Findings per batch
            max_batches: Maximum number of batches
            max_runtime_hours: Maximum runtime in hours
        """
        print("🚀 MASSIVE DATASET GENERATION - PRODUCTION MODE")
        print("=" * 60)
        print(f"Batch Size: {batch_size:,} findings")
        print(f"Max Batches: {max_batches}")
        print(f"Max Runtime: {max_runtime_hours} hours")
        print(f"GPU Optimized: {self.gpu_optimized}")
        print()

        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)

        self.stats["start_time"] = time.time()
        start_time = self.stats["start_time"]

        # Start resource monitoring
        monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        monitor_thread.start()

        all_results = []
        batch_num = 1

        try:
            while self.running and batch_num <= max_batches:
                elapsed_hours = (time.time() - start_time) / 3600
                if elapsed_hours >= max_runtime_hours:
                    print(f"⏰ Reached maximum runtime of {max_runtime_hours} hours")
                    break

                print(f"\n🔄 BATCH {batch_num}/{max_batches} (Elapsed: {elapsed_hours:.2f}h)")
                print("-" * 40)

                # Calculate producer counts for this batch
                producer_counts = self._calculate_producer_counts(batch_size)

                # Generate batch
                batch_start = time.time()
                result = self._generate_batch(producer_counts, output_dir_path, batch_num)
                batch_end = time.time()

                if result:
                    all_results.append(result)
                    self.stats["batches_completed"] += 1
                    self.stats["total_findings"] += result["data_summary"]["total_findings"]
                    self.stats["total_correlations"] += result["data_summary"]["total_correlations"]

                    batch_time = batch_end - batch_start
                    print(f"  ✓ Batch {batch_num} completed in {batch_time:.2f}s")
                else:
                    self.stats["errors"].append(f"Batch {batch_num} failed")
                    print(f"❌ Batch {batch_num} failed")

                batch_num += 1

        except Exception as e:
            self.stats["errors"].append(str(e))
            print(f"❌ Error: {e}")

        finally:
            self.running = False
            self.stats["end_time"] = time.time()

        # Generate final report
        return self._generate_final_report(all_results, output_dir_path)

    def _calculate_producer_counts(self, total_findings: int) -> Dict[str, int]:
        """Calculate balanced producer counts for optimal generation."""
        producers = self.pipeline.get_available_producers()

        # Base distribution weights
        weights = {
            "processes": 0.25,
            "network": 0.20,
            "kernel_params": 0.15,
            "filesystem": 0.15,
            "modules": 0.10,
            "ioc": 0.08,
            "mac": 0.04,
            "suid": 0.03
        }

        counts = {}
        for producer in producers:
            if producer in weights:
                count = max(1, int(total_findings * weights[producer]))
                counts[producer] = count

        # Ensure we hit the target total
        current_total = sum(counts.values())
        if current_total < total_findings:
            # Add remainder to processes
            counts["processes"] += (total_findings - current_total)

        return counts

    def _generate_batch(self, producer_counts: Dict[str, int], output_dir: Path, batch_num: int) -> Optional[Dict[str, Any]]:
        """Generate a single batch of data."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = output_dir / f"batch_{batch_num:03d}_{timestamp}.json"

            result = self.pipeline.execute_pipeline(
                producer_counts=producer_counts,
                output_path=str(output_path),
                output_format="optimized_json",
                compress=True,
                save_intermediate=False
            )

            return result

        except Exception as e:
            print(f"❌ Batch generation failed: {e}")
            return None

    def _generate_final_report(self, all_results: list, output_dir: Path) -> Dict[str, Any]:
        """Generate comprehensive final report."""
        end_time = self.stats["end_time"]
        start_time = self.stats["start_time"]
        total_runtime = end_time - start_time

        final_report = {
            "generation_stats": {
                "total_runtime_seconds": total_runtime,
                "total_runtime_hours": total_runtime / 3600,
                "batches_completed": self.stats["batches_completed"],
                "total_findings": self.stats["total_findings"],
                "total_correlations": self.stats["total_correlations"],
                "findings_per_second": self.stats["total_findings"] / total_runtime if total_runtime > 0 else 0,
                "gpu_optimized": self.gpu_optimized,
                "errors": self.stats["errors"]
            },
            "batch_results": all_results,
            "system_info": {
                "cpu_count": os.cpu_count(),
                "memory_gb": psutil.virtual_memory().total / (1024**3) if HAS_PSUTIL and psutil else 0,
                "platform": sys.platform
            },
            "output_directory": str(output_dir)
        }

        # Save final report
        report_path = output_dir / "generation_report.json"
        with open(report_path, 'w') as f:
            json.dump(final_report, f, indent=2, default=str)

        return final_report

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate massive synthetic datasets for fine-tuning (Production Mode)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "--output-dir", "-o",
        default="./massive_datasets",
        help="Output directory for generated datasets"
    )

    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=5000,
        help="Findings per batch"
    )

    parser.add_argument(
        "--max-batches", "-m",
        type=int,
        default=20,
        help="Maximum number of batches to generate"
    )

    parser.add_argument(
        "--max-hours", "-t",
        type=float,
        default=2.0,
        help="Maximum runtime in hours"
    )

    parser.add_argument(
        "--gpu",
        action="store_true",
        default=True,
        help="Enable GPU optimization"
    )

    parser.add_argument(
        "--no-gpu",
        action="store_false",
        dest="gpu",
        help="Disable GPU optimization"
    )

    parser.add_argument(
        "--conservative",
        action="store_true",
        default=False,
        help="Use conservative parallel processing"
    )

    args = parser.parse_args()

    # Initialize generator
    generator = DatasetGenerator(
        gpu_optimized=args.gpu,
        conservative_parallel=args.conservative
    )

    # Generate massive dataset
    result = generator.generate_massive_dataset(
        output_dir=args.output_dir,
        batch_size=args.batch_size,
        max_batches=args.max_batches,
        max_runtime_hours=args.max_hours
    )

    # Print final summary
    stats = result["generation_stats"]
    print("\n🎉 GENERATION COMPLETE!")
    print("=" * 60)
    print(f"Runtime: {stats['total_runtime_hours']:.2f} hours")
    print(f"Batches: {stats['batches_completed']}")
    print(f"Total Findings: {stats['total_findings']:,}")
    print(f"Total Correlations: {stats['total_correlations']:,}")
    print(f"Findings/sec: {stats['findings_per_second']:.1f}")
    print(f"Output: {result['output_directory']}")

    if stats["errors"]:
        print(f"Errors: {len(stats['errors'])}")
        for error in stats["errors"][:3]:
            print(f"  • {error}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
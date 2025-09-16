#!/usr/bin/env python3
"""
Memory profiling for test_pipeline_comprehensive.py end-to-end test.
Focuses on the run_pipeline test that's causing memory leaks and recursion issues.
"""

import tracemalloc
import gc
import os
import sys
from pathlib import Path
import json
import tempfile
from unittest.mock import patch, MagicMock

# Add agent directory to path
sys.path.insert(0, str(Path(__file__).parent / 'agent'))

def get_memory_usage():
    """Get current memory usage in MB using tracemalloc"""
    current, peak = tracemalloc.get_traced_memory()
    return current / 1024 / 1024

def profile_memory_operation(operation_func, operation_name, *args, **kwargs):
    """Profile memory usage for a specific operation"""
    print(f"\n=== Profiling {operation_name} ===")

    # Force garbage collection before starting
    gc.collect()
    tracemalloc.reset_peak()

    initial_memory = get_memory_usage()
    tracemalloc.start()

    try:
        result = operation_func(*args, **kwargs)
        current_memory = get_memory_usage()
        current, peak = tracemalloc.get_traced_memory()

        # Get top memory consumers before stopping
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')

        tracemalloc.stop()

        memory_delta = current_memory - initial_memory
        print(f"  Memory before: {initial_memory:.2f} MB")
        print(f"  Memory after: {current_memory:.2f} MB")
        print(f"  Memory delta: {memory_delta:+.2f} MB")
        print(f"  Tracemalloc current: {current / 1024 / 1024:.2f} MB")
        print(f"  Tracemalloc peak: {peak / 1024 / 1024:.2f} MB")

        print("  Top memory consumers:")
        for i, stat in enumerate(top_stats[:15]):  # Show more for detailed analysis
            print(f"    {i+1}. {stat.traceback.format()[-1]}: {stat.size / 1024 / 1024:.2f} MB")

        return result, {
            'operation': operation_name,
            'memory_before': initial_memory,
            'memory_after': current_memory,
            'memory_delta': memory_delta,
            'tracemalloc_current': current / 1024 / 1024,
            'tracemalloc_peak': peak / 1024 / 1024,
            'top_consumers': [
                {
                    'file': stat.traceback.format()[-1],
                    'size_mb': stat.size / 1024 / 1024
                } for stat in top_stats[:15]
            ]
        }

    except Exception as e:
        tracemalloc.stop()
        print(f"  Error in {operation_name}: {e}")
        import traceback
        traceback.print_exc()
        raise

def create_test_data():
    """Create test data similar to the comprehensive test"""
    sample_report_data = {
        "meta": {
            "hostname": "test-host",
            "kernel": "5.4.0-test",
            "host_id": None,
            "scan_id": None
        },
        "summary": {
            "finding_count_total": 3,
            "finding_count_emitted": 3
        },
        "results": [
            {
                "scanner": "process",
                "finding_count": 2,
                "findings": [
                    {
                        "id": "f1",
                        "title": "Suspicious process",
                        "severity": "high",
                        "risk_score": 80,
                        "metadata": {"cmdline": "/usr/bin/suspicious", "pid": 1234},
                        "tags": []
                    },
                    {
                        "id": "f2",
                        "title": "Normal process",
                        "severity": "low",
                        "risk_score": 10,
                        "metadata": {"cmdline": "/bin/bash", "pid": 5678},
                        "tags": []
                    }
                ]
            },
            {
                "scanner": "network",
                "finding_count": 1,
                "findings": [
                    {
                        "id": "f3",
                        "title": "Listening port",
                        "severity": "medium",
                        "risk_score": 40,
                        "metadata": {"port": 8080, "state": "LISTEN"},
                        "tags": []
                    }
                ]
            }
        ],
        "collection_warnings": [],
        "scanner_errors": [],
        "summary_extension": {"total_risk_score": 130, "emitted_risk_score": 130}
    }

    # Create temporary report file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_report_data, f)
        return Path(f.name)

def test_run_pipeline_memory():
    """Test the run_pipeline function with memory profiling"""
    print("Testing run_pipeline memory usage...")

    # Set up environment
    os.environ['AGENT_LOAD_HF_CORPUS'] = '0'
    os.environ['AGENT_PERF_BASELINE_PATH'] = '/tmp/perf_baseline.json'
    os.environ['AGENT_BASELINE_DB'] = '/tmp/test_baseline.db'
    os.environ['AGENT_MAX_SUMMARY_ITERS'] = '1'
    os.environ['AGENT_LOAD_HF_CORPUS'] = ''
    os.environ['AGENT_MAX_WORKERS'] = '1'

    # Create test report
    report_path = create_test_data()

    try:
        # Import required modules
        from agent.pipeline import run_pipeline
        from agent import config

        # Mock configuration to avoid loading issues
        mock_config = MagicMock()
        mock_config.performance = MagicMock(parallel_baseline=False, workers=1)
        mock_config.thresholds = MagicMock(summarization_risk_sum=0, process_novelty_distance=1.0)
        mock_config.paths = MagicMock(rule_dirs=[], policy_allowlist=[])

                # Mock LLM provider with proper Summaries object
        from agent.models import Summaries
        mock_summaries = Summaries(
            executive_summary="Test executive summary",
            analyst={"correlation_count": 2, "top_findings_count": 3},
            metrics={'tokens_prompt': 100, 'tokens_completion': 50}
        )
        mock_llm = MagicMock()
        mock_llm.summarize.return_value = (mock_summaries, MagicMock(
            model_name="test", provider_name="test", latency_ms=10,
            tokens_prompt=100, tokens_completion=50
        ))

        # Mock data governor properly
        mock_governor = MagicMock()
        mock_governor.redact_for_llm.side_effect = lambda x: x  # Return input unchanged
        mock_governor.redact_output_narratives.side_effect = lambda x: x  # Return input unchanged

        with patch('agent.pipeline.load_config', return_value=mock_config), \
             patch('agent.pipeline.get_llm_provider', return_value=mock_llm), \
             patch('agent.data_governance.get_data_governor', return_value=mock_governor):

            # Profile the run_pipeline execution
            _, profile = profile_memory_operation(
                run_pipeline,
                "run_pipeline_end_to_end",
                report_path
            )

            return profile

    finally:
        # Clean up
        if report_path.exists():
            report_path.unlink()

def test_multiple_runs():
    """Test multiple runs to check for accumulation"""
    print("\n" + "="*60)
    print("TESTING MULTIPLE RUNS FOR MEMORY ACCUMULATION")
    print("="*60)

    profiles = []

    for i in range(3):
        print(f"\n--- Run {i+1}/3 ---")
        try:
            profile = test_run_pipeline_memory()
            profiles.append(profile)
            print(f"Run {i+1} completed successfully")
        except Exception as e:
            print(f"Run {i+1} failed: {e}")
            break

        # Force garbage collection between runs
        gc.collect()

    return profiles

def analyze_memory_patterns(profiles):
    """Analyze memory patterns across runs"""
    if not profiles:
        return {}

    print("\n" + "="*60)
    print("MEMORY PATTERN ANALYSIS")
    print("="*60)

    deltas = [p['memory_delta'] for p in profiles]
    peaks = [p['tracemalloc_peak'] for p in profiles]

    analysis = {
        'total_runs': len(profiles),
        'avg_memory_delta': sum(deltas) / len(deltas) if deltas else 0,
        'max_memory_delta': max(deltas) if deltas else 0,
        'avg_peak_memory': sum(peaks) / len(peaks) if peaks else 0,
        'max_peak_memory': max(peaks) if peaks else 0,
        'memory_accumulation': deltas[-1] - deltas[0] if len(deltas) > 1 else 0
    }

    print(f"Total runs: {analysis['total_runs']}")
    print(".2f")
    print(".2f")
    print(".2f")
    print(".2f")
    print(".2f")

    if analysis['memory_accumulation'] > 1.0:
        print("⚠️  WARNING: Significant memory accumulation detected!")
    else:
        print("✅ No significant memory accumulation")

    return analysis

def main():
    """Run memory profiling for the pipeline test"""
    print("Starting memory profiling for test_pipeline_comprehensive.py run_pipeline test...")

    try:
        # Test single run
        print("\n" + "="*60)
        print("SINGLE RUN TEST")
        print("="*60)

        single_profile = test_run_pipeline_memory()

        # Test multiple runs
        multi_profiles = test_multiple_runs()

        # Analyze patterns
        all_profiles = [single_profile] + multi_profiles
        analysis = analyze_memory_patterns(all_profiles)

        # Save results
        results = {
            'timestamp': json.dumps(None),  # Will be set by json.dumps
            'test_description': 'Memory profiling of test_pipeline_comprehensive.py run_pipeline test',
            'single_run': single_profile,
            'multiple_runs': multi_profiles,
            'analysis': analysis
        }

        # Set timestamp
        from datetime import datetime
        results['timestamp'] = datetime.now().isoformat()

        results_file = Path('/tmp/test_pipeline_memory_profile.json')
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n=== Profiling Complete ===")
        print(f"Results saved to: {results_file}")

        # Check for memory issues
        if analysis.get('memory_accumulation', 0) > 5.0:
            print("🚨 CRITICAL: High memory accumulation detected in test!")
            return 1
        elif analysis.get('max_memory_delta', 0) > 50.0:
            print("⚠️  WARNING: High memory usage detected in test!")
            return 1
        else:
            print("✅ Test memory usage appears normal")
            return 0

    except Exception as e:
        print(f"Error during profiling: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
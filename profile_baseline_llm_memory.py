#!/usr/bin/env python3
"""
Targeted memory profiling for baseline operations and LLM calls.
Focuses on the areas most likely to cause memory leaks.
"""

import tracemalloc
import gc
import os
import sys
from pathlib import Path
import json
from datetime import datetime

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
        for i, stat in enumerate(top_stats[:10]):  # Show more for detailed analysis
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
                } for stat in top_stats[:10]
            ]
        }

    except Exception as e:
        tracemalloc.stop()
        print(f"  Error in {operation_name}: {e}")
        raise

def main():
    """Run targeted memory profiling for baseline and LLM operations"""
    print("Starting targeted memory profiling for baseline and LLM operations...")

    # Change to agent directory for proper imports
    agent_dir = Path(__file__).parent / 'agent'
    os.chdir(agent_dir)

    # Set environment variables
    os.environ['AGENT_LOAD_HF_CORPUS'] = '0'
    os.environ['AGENT_PERF_BASELINE_PATH'] = '/tmp/perf_baseline.json'

    try:
        # Import required modules
        from agent.baseline import BaselineStore
        from agent.llm_provider import get_llm_provider
        from agent.models import AgentState, Report, ScannerResult, Finding, Correlation, Summaries, Reductions, ActionItem
        import tempfile

        profiles = []

        # Test 1: Baseline database operations
        print("\n" + "="*60)
        print("TEST 1: Baseline Database Operations")
        print("="*60)

        try:
            store = BaselineStore(Path("agent_baseline.db"))

            # Test recording metrics multiple times with larger datasets
            for i in range(5):
                # Create larger metrics dataset
                metrics = {}
                for j in range(50):  # 50 metrics per scan
                    metrics[f'finding.count.category_{j}'] = float(10 + i + j)
                    metrics[f'risk.sum.category_{j}'] = float(50 + i * 10 + j * 2)
                    metrics[f'module.count.type_{j}'] = float(5 + i + j)

                _, profile = profile_memory_operation(
                    store.record_metrics,
                    f"record_metrics_scan_{i+1}_50_metrics",
                    f"test-host-{i+1}",
                    f"test-scan-{i+1}",
                    metrics,
                    history_limit=20  # Keep more history
                )
                profiles.append(profile)

                # Also test update_and_diff with larger finding sets
                findings = []
                for j in range(100):  # 100 findings per scan
                    findings.append((
                        f'scanner_{j % 5}',
                        Finding(
                            id=f'finding_{i}_{j}',
                            title=f'Test finding {i}_{j} with some descriptive content to increase memory usage',
                            severity='medium',
                            risk_score=5 + j % 10,
                            description=f'Description for finding {i}_{j}',
                            metadata={'path': f'/test/path/{i}/{j}', 'size': 1000 + j * 10},
                            category=f'category_{j % 10}',
                            tags=[f'tag_{k}' for k in range(j % 3)]
                        )
                    ))

                _, profile = profile_memory_operation(
                    store.update_and_diff,
                    f"update_and_diff_scan_{i+1}_100_findings",
                    f"test-host-{i+1}",
                    findings
                )
                profiles.append(profile)

        except Exception as e:
            print(f"Baseline operations failed: {e}")

        # Test 2: LLM operations with varying context sizes
        print("\n" + "="*60)
        print("TEST 2: LLM Operations with Varying Context Sizes")
        print("="*60)

        try:
            llm_provider = get_llm_provider()

            # Create test data with increasing complexity
            test_sizes = [1, 5, 10, 20]  # Number of findings

            for size in test_sizes:
                # Create mock reductions with increasing size
                mock_reductions = {
                    'module_summary': {'module_count': size, 'notable_modules': [f'module_{i}' for i in range(size)]},
                    'suid_summary': {'unexpected_suid': [f'/path/suid_{i}' for i in range(size)]},
                    'network_summary': {'listen_count': size},
                    'top_findings': [
                        {
                            'id': f'finding_{i}',
                            'title': f'Test finding {i} with some additional context to increase memory usage',
                            'severity': 'medium',
                            'risk_score': 5.0 + i,
                            'category': 'test',
                            'tags': ['test', 'memory_test'],
                            'metadata': {'path': f'/test/path/{i}', 'size': 1000 + i * 100},
                            'risk_subscores': {'impact': 3.0, 'exposure': 2.0, 'anomaly': 1.0, 'confidence': 0.8}
                        } for i in range(size)
                    ]
                }

                # Convert to Reductions object
                reductions_obj = Reductions(**mock_reductions)

                # Create mock correlations
                correlations = [
                    Correlation(
                        id=f'corr_{i}',
                        title=f'Test correlation {i}',
                        rationale=f'Test rationale {i}',
                        related_finding_ids=[f'finding_{i}'],
                        risk_score_delta=2,
                        tags=['test'],
                        severity='low'
                    ) for i in range(min(size, 3))  # Fewer correlations
                ]

                # Create mock actions
                actions = [
                    ActionItem(priority=i+1, action=f'Test action {i}', correlation_refs=[f'corr_{i}'])
                    for i in range(min(size, 2))
                ]

                # Test LLM summarize operation
                _, profile = profile_memory_operation(
                    llm_provider.summarize,
                    f"summarize_{size}_findings",
                    reductions_obj,
                    correlations,
                    actions,
                    skip=False,
                    previous=None,
                    skip_reason=None,
                    baseline_context=None
                )
                profiles.append(profile)

        except Exception as e:
            print(f"LLM operations failed: {e}")
            import traceback
            traceback.print_exc()

        # Test 3: Memory accumulation test (run operations in sequence)
        print("\n" + "="*60)
        print("TEST 3: Memory Accumulation Test")
        print("="*60)

        try:
            print("Running 10 iterations of baseline + LLM operations to check for accumulation...")

            for iteration in range(10):
                # Force GC between iterations
                gc.collect()

                initial_mem = get_memory_usage()
                print(f"Iteration {iteration + 1}/10 - Memory before: {initial_mem:.2f} MB")

                # Quick baseline operation
                store = BaselineStore(Path("agent_baseline.db"))
                metrics = {'test_metric': float(iteration)}
                store.record_metrics(f"iter-host-{iteration}", f"iter-scan-{iteration}", metrics)

                # Quick LLM operation
                llm_provider = get_llm_provider()
                small_reductions = Reductions(
                    top_findings=[{'id': f'iter_{iteration}', 'title': f'Iteration {iteration}'}]
                )
                llm_provider.summarize(small_reductions, [], [], skip=True)

                final_mem = get_memory_usage()
                delta = final_mem - initial_mem
                print(f"Iteration {iteration + 1}/10 - Memory after: {final_mem:.2f} MB (Δ{delta:+.2f} MB)")

                if delta > 1.0:  # More than 1MB growth
                    print(f"WARNING: Significant memory growth detected in iteration {iteration + 1}")

        except Exception as e:
            print(f"Memory accumulation test failed: {e}")

        # Save profiling results
        results = {
            'timestamp': datetime.now().isoformat(),
            'test_description': 'Targeted memory profiling for baseline and LLM operations',
            'profiles': profiles,
            'summary': {
                'total_operations': len(profiles),
                'max_memory_delta': max((p['memory_delta'] for p in profiles), default=0),
                'max_peak_memory': max((p['tracemalloc_peak'] for p in profiles), default=0)
            }
        }

        results_file = Path('/tmp/targeted_memory_profile.json')
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n=== Profiling Complete ===")
        print(f"Results saved to: {results_file}")

        # Print summary
        print("\n=== Memory Usage Summary ===")
        for profile in profiles:
            delta = profile['memory_delta']
            peak = profile['tracemalloc_peak']
            print(f"{profile['operation']:30}: Δ{delta:+6.2f} MB, Peak: {peak:6.2f} MB")

    except Exception as e:
        print(f"Error during profiling: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
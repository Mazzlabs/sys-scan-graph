#!/usr/bin/env python3
"""
Comprehensive memory profiling for full pipeline execution.
Profiles memory usage across all pipeline stages including summarize with LLM calls.
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

def profile_pipeline_stage(stage_func, stage_name, *args, **kwargs):
    """Profile memory usage for a single pipeline stage"""
    print(f"\n=== Profiling {stage_name} ===")

    # Force garbage collection before starting
    gc.collect()
    tracemalloc.reset_peak()

    initial_memory = get_memory_usage()
    tracemalloc.start()

    try:
        result = stage_func(*args, **kwargs)
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
        for i, stat in enumerate(top_stats[:5]):
            print(f"    {i+1}. {stat.traceback.format()[-1]}: {stat.size / 1024 / 1024:.2f} MB")

        return result, {
            'stage': stage_name,
            'memory_before': initial_memory,
            'memory_after': current_memory,
            'memory_delta': memory_delta,
            'tracemalloc_current': current / 1024 / 1024,
            'tracemalloc_peak': peak / 1024 / 1024,
            'top_consumers': [
                {
                    'file': stat.traceback.format()[-1],
                    'size_mb': stat.size / 1024 / 1024
                } for stat in top_stats[:5]
            ]
        }

    except Exception as e:
        tracemalloc.stop()
        print(f"  Error in {stage_name}: {e}")
        raise

def main():
    """Run full pipeline with comprehensive memory profiling"""
    print("Starting comprehensive pipeline memory profiling...")

    # Change to agent directory for proper imports
    agent_dir = Path(__file__).parent / 'agent'
    os.chdir(agent_dir)

    # Set environment variables to minimize external dependencies
    os.environ['AGENT_LOAD_HF_CORPUS'] = '0'  # Disable corpus loading
    os.environ['AGENT_PERF_BASELINE_PATH'] = '/tmp/perf_baseline.json'

    try:
        # Import pipeline modules
        from agent.pipeline import (
            load_report, augment, correlate, reduce, summarize,
            actions, build_output, run_pipeline, AgentState
        )
        from agent.models import EnrichedOutput
        import tempfile

        # Create a temporary test report file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Create a minimal test report
            test_report = {
                "meta": {
                    "host_id": "test-host-001",
                    "scan_id": "test-scan-001",
                    "timestamp": datetime.now().isoformat(),
                    "scanner_version": "test-1.0"
                },
                "summary": {
                    "finding_count_total": 2,
                    "finding_count_emitted": 2,
                    "severity_counts": {"medium": 1, "low": 1}
                },
                "summary_extension": {
                    "total_risk_score": 7,
                    "emitted_risk_score": 7
                },
                "results": [
                    {
                        "scanner": "test_scanner",
                        "finding_count": 2,
                        "findings": [
                            {
                                "id": "test-finding-1",
                                "title": "Test SUID binary",
                                "severity": "medium",
                                "risk_score": 5.0,
                                "category": "privilege",
                                "tags": ["suid", "baseline:new"],
                                "metadata": {"path": "/usr/bin/test", "exe": "/usr/bin/test"},
                                "risk_subscores": {"impact": 3.0, "exposure": 2.0, "anomaly": 1.0, "confidence": 0.8}
                            },
                            {
                                "id": "test-finding-2",
                                "title": "Test routing config",
                                "severity": "low",
                                "risk_score": 2.0,
                                "category": "network",
                                "tags": ["routing"],
                                "metadata": {"config": "/etc/sysctl.conf"},
                                "risk_subscores": {"impact": 1.0, "exposure": 1.0, "anomaly": 0.5, "confidence": 0.6}
                            }
                        ]
                    }
                ]
            }
            json.dump(test_report, f)
            test_report_path = Path(f.name)

        print(f"Created test report at: {test_report_path}")

        # Initialize state
        state = AgentState()
        profiles = []

        # Profile each stage
        state, profile = profile_pipeline_stage(load_report, "load_report", state, test_report_path)
        profiles.append(profile)

        state, profile = profile_pipeline_stage(augment, "augment", state)
        profiles.append(profile)

        state, profile = profile_pipeline_stage(correlate, "correlate", state)
        profiles.append(profile)

        state, profile = profile_pipeline_stage(reduce, "reduce", state)
        profiles.append(profile)

        # This is the critical stage - summarize with LLM calls
        try:
            state, profile = profile_pipeline_stage(summarize, "summarize", state)
            profiles.append(profile)
        except Exception as e:
            print(f"Warning: Summarize stage failed with error: {e}")
            print("Continuing with other stages...")
            # Create a dummy profile for summarize
            profiles.append({
                'stage': 'summarize',
                'memory_before': 0.0,
                'memory_after': 0.0,
                'memory_delta': 0.0,
                'tracemalloc_current': 0.0,
                'tracemalloc_peak': 0.0,
                'error': str(e)
            })

        state, profile = profile_pipeline_stage(actions, "actions", state)
        profiles.append(profile)

        # This is the final stage - build_output
        try:
            state, profile = profile_pipeline_stage(build_output, "build_output", state, test_report_path)
            profiles.append(profile)
        except Exception as e:
            print(f"Warning: build_output stage failed with error: {e}")
            print("Continuing with profiling completion...")
            # Create a dummy profile for build_output
            profiles.append({
                'stage': 'build_output',
                'memory_before': 0.0,
                'memory_after': 0.0,
                'memory_delta': 0.0,
                'tracemalloc_current': 0.0,
                'tracemalloc_peak': 0.0,
                'error': str(e)
            })

        # Save profiling results
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_memory_start': get_memory_usage(),
            'profiles': profiles,
            'final_memory': get_memory_usage()
        }

        results_file = Path('/tmp/pipeline_memory_profile.json')
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n=== Profiling Complete ===")
        print(f"Results saved to: {results_file}")

        # Print summary
        print("\n=== Memory Usage Summary ===")
        for profile in profiles:
            delta = profile['memory_delta']
            peak = profile['tracemalloc_peak']
            print(f"{profile['stage']:15}: Δ{delta:+6.2f} MB, Peak: {peak:6.2f} MB")

        # Cleanup
        test_report_path.unlink(missing_ok=True)

    except Exception as e:
        print(f"Error during profiling: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())
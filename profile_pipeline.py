#!/usr/bin/env python3
import cProfile
import pstats
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / 'agent'))

from legacy.pipeline import run_pipeline

def profile_pipeline():
    report_path = Path('/tmp/sample_report.json')
    if not report_path.exists():
        print(f"Report file not found: {report_path}")
        return

    print("Profiling pipeline execution...")
    profiler = cProfile.Profile()
    profiler.enable()

    try:
        result = run_pipeline(report_path)
        print("Pipeline completed successfully")
    except Exception as e:
        print(f"Pipeline failed: {e}")
        return

    profiler.disable()

    # Print stats
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    print("\n=== Top 20 functions by cumulative time ===")
    stats.print_stats(20)

    print("\n=== Top 20 functions by time per call ===")
    stats.sort_stats('time')
    stats.print_stats(20)

if __name__ == '__main__':
    profile_pipeline()
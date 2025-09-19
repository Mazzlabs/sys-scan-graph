"""
Command-line interface for synthetic data generation.
"""

import argparse
import sys
import os
sys.path.append(os.path.dirname(__file__))

from synthetic_data_generator import SyntheticDataGenerator

def main():
    """CLI main function."""
    parser = argparse.ArgumentParser(description="Generate synthetic security scan data")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")
    parser.add_argument("--processes", type=int, default=10, help="Number of process findings")
    parser.add_argument("--network", type=int, default=10, help="Number of network findings")
    parser.add_argument("--verify", action="store_true", default=True, help="Verify generated data")
    parser.add_argument("--no-verify", action="store_false", dest="verify", help="Skip verification")
    parser.add_argument("--max-iterations", type=int, default=5, help="Maximum generation iterations")

    args = parser.parse_args()

    # Create generator
    generator = SyntheticDataGenerator()

    # Generate data
    producer_counts = {
        "processes": args.processes,
        "network": args.network
    }

    print(f"Generating synthetic data with {sum(producer_counts.values())} findings...")

    try:
        ground_truth_data = generator.generate_ground_truth_data(
            producer_counts=producer_counts,
            verify=args.verify,
            max_iterations=args.max_iterations
        )

        # Save to file
        generator.save_to_file(ground_truth_data, os.path.abspath(args.output))

        print("Synthetic data generation completed!")
        print(f"Output saved to: {args.output}")

        # Show summary
        findings = ground_truth_data["enriched_findings"]
        print(f"Total findings: {len(findings)}")

        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print("Findings by severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
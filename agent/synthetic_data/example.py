"""
Example script demonstrating synthetic data generation.
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from synthetic_data_generator import SyntheticDataGenerator

def main():
    """Main example function."""
    print("Synthetic Data Generation Example")
    print("=" * 40)

    # Create generator
    generator = SyntheticDataGenerator()

    # List available producers
    producers = generator.producer_registry.list_producers()
    print(f"Available producers: {producers}")

    # Generate data (disable verification for initial testing)
    print("\nGenerating synthetic data...")
    try:
        ground_truth_data = generator.generate_ground_truth_data(
            producer_counts={"processes": 5, "network": 5},
            verify=False,  # Disable verification for testing
            max_iterations=3
        )

        print(f"Generated {len(ground_truth_data['enriched_findings'])} findings")

        # Save to file
        output_file = os.path.join(os.getcwd(), "synthetic_ground_truth_example.json")
        generator.save_to_file(ground_truth_data, output_file)

        # Show summary
        findings = ground_truth_data["enriched_findings"]
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print("\nFindings by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        print(f"\nCorrelations: {len(ground_truth_data['correlations'])}")
        print(f"Actions: {len(ground_truth_data['actions'])}")

    except ValueError as e:
        print(f"Failed to generate data: {e}")
        return 1

    print("\nExample completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
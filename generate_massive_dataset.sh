#!/bin/bash
# Massive Dataset Generation Launcher
# Run this script to generate huge synthetic datasets for fine-tuning

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/agent/synthetic_data/generate_dataset.py"

echo "🚀 MASSIVE DATASET GENERATION LAUNCHER"
echo "======================================"
echo "Project Root: $SCRIPT_DIR"
echo "Script: $PYTHON_SCRIPT"
echo

# Check if Python script exists
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "❌ Error: Dataset generation script not found at $PYTHON_SCRIPT"
    echo "Please ensure you're running this from the project root directory."
    exit 1
fi

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3.7+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Error: Python $PYTHON_VERSION detected. Minimum required: $REQUIRED_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Default parameters for massive generation (optimized for T4 GPU)
DEFAULT_ARGS=(
    "--output-dir" "./massive_datasets"
    "--batch-size" "5000"
    "--max-batches" "24"  # ~2 hours at ~5min per batch
    "--max-hours" "2.0"
    "--gpu"
)

echo
echo "📋 CONFIGURATION:"
echo "  Output Directory: ./massive_datasets"
echo "  Batch Size: 5,000 findings per batch"
echo "  Max Batches: 24 (scalable)"
echo "  Max Runtime: 2.0 hours"
echo "  GPU Optimization: Enabled"
echo "  Expected Output: ~120K+ findings"
echo

# Allow overriding with command line arguments
if [ $# -eq 0 ]; then
    echo "🔄 Using default configuration..."
    echo "💡 Tip: Run with --help to see all options"
    echo
    ARGS=("${DEFAULT_ARGS[@]}")
else
    echo "🔧 Using custom configuration..."
    echo
    ARGS=("$@")
fi

echo "🚀 EXECUTING COMMAND:"
echo "cd $SCRIPT_DIR && python3 $PYTHON_SCRIPT ${ARGS[*]}"
echo

# Change to project directory and run
cd "$SCRIPT_DIR"
python3 "$PYTHON_SCRIPT" "${ARGS[@]}"

EXIT_CODE=$?
echo
echo "📊 EXIT CODE: $EXIT_CODE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ MASSIVE DATASET GENERATION COMPLETED SUCCESSFULLY!"
    echo
    echo "📁 Check your output directory: $SCRIPT_DIR/massive_datasets"
    echo "📄 Generation report: $SCRIPT_DIR/massive_datasets/generation_report.json"
    echo
    echo "🎯 Ready for fine-tuning with substantial synthetic dataset!"
else
    echo "❌ Dataset generation failed with exit code $EXIT_CODE"
    echo
    echo "🔍 Check the error messages above for details"
    echo "💡 Common issues:"
    echo "   - Ensure all dependencies are installed"
    echo "   - Check available disk space"
    echo "   - Verify GPU availability (if using --gpu)"
fi

exit $EXIT_CODE
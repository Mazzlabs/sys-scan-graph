# Installation Guide

This guide covers all available installation methods for sys-scan-graph.

## Debian/Ubuntu (Recommended)

### Official APT Repository

```bash
# Add the Mazzlabs repository
echo "deb [signed-by=/usr/share/keyrings/mazzlabs-archive-keyring.gpg] https://apt.mazzlabs.works/ stable main" | sudo tee /etc/apt/sources.list.d/mazzlabs.list

# Import the GPG key
curl -fsSL https://apt.mazzlabs.works/mazzlabs-archive-keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/mazzlabs-archive-keyring.gpg

# Update package lists
sudo apt update

# Install sys-scan-graph
sudo apt install sys-scan-graph
```

### Verify Installation

```bash
# Check version
sys-scan --version
sys-scan-graph-agent --version

# Run a basic scan
sys-scan --canonical --modules-summary --min-severity info
```

## Build from Source

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install build-essential cmake git python3 python3-venv python3-pip

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install cmake git python3 python3-devel
```

### Build Process

```bash
# Clone repository
git clone https://github.com/Mazzlabs/sys-scan-graph.git
cd sys-scan-graph

# Build core scanner
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Set up Python environment
cd agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run from Source

```bash
# Basic scan
./build/sys-scan --canonical --modules-summary --min-severity info > report.json

# With intelligence layer
./build/sys-scan --canonical --output report.json
python -m agent.cli analyze --report report.json --out enriched_report.json
```

## Docker Installation

```bash
# Pull the official image
docker pull mazzlabs/sys-scan-graph:latest

# Run a scan
docker run --rm -v $(pwd):/output mazzlabs/sys-scan-graph:latest \
  sys-scan --canonical --output /output/report.json

# Run with intelligence layer
docker run --rm -v $(pwd):/output mazzlabs/sys-scan-graph:latest \
  sys-scan-graph-agent analyze --report /output/report.json --out /output/enriched.json
```

## Configuration

After installation, you may want to:

1. Review the default configuration in `/etc/sys-scan-graph/config.yaml`
2. Set up baseline databases for your environment
3. Configure LLM providers for intelligence features
4. Set up log aggregation and monitoring

## Troubleshooting

### Common Issues

**Import Errors**: If you encounter Python import errors, ensure you're using the correct Python environment and all dependencies are installed.

**Permission Errors**: The scanner may require elevated permissions to access system information. Run with `sudo` if needed.

**LLM Provider Issues**: Check your API keys and network connectivity for LLM-based features.

### Getting Help

- Check the [troubleshooting section](https://github.com/Mazzlabs/sys-scan-graph/wiki/Troubleshooting) in the GitHub Wiki
- File an issue on [GitHub Issues](https://github.com/Mazzlabs/sys-scan-graph/issues)
- Ask questions in [GitHub Discussions](https://github.com/Mazzlabs/sys-scan-graph/discussions)

## Next Steps

Once installed, you can:

1. Run your first scan with `sys-scan --help`
2. Explore the intelligence layer with `sys-scan-graph-agent --help`
3. Review the [CLI Guide](../CLI-Guide.md) for detailed usage
4. Set up automated scanning in your CI/CD pipeline
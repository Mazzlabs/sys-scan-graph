# sys-scan-graph

<div align="center">
  <img src="assets/sys-scan-graph_badge.jpg" alt="sys-scan-graph Logo" width="500"/>
</div>

## System Security Scanner & Intelligence Graph

**Sys-Scan-Graph** is a high-speed security analysis tool that transforms raw data from multiple security surfaces into a unified, actionable report.

<div align="center">
  <a href="https://codescene.io/projects/71206">
    <img src="https://codescene.io/images/analyzed-by-codescene-badge.svg" alt="CodeScene Analysis" />
  </a>
  <a href="https://codescene.io/projects/71206">
    <img src="https://codescene.io/projects/71206/status-badges/average-code-health" alt="CodeScene Average Code Health" />
  </a>
  <a href="https://codescene.io/projects/71206">
    <img src="https://codescene.io/projects/71206/status-badges/system-mastery" alt="CodeScene System Mastery" />
  </a>
</div>

It combines a high-performance C++ scanning engine with a Python-based intelligence layer to deliver deterministic, reproducible results. The core engine gathers data and outputs it in multiple formats (JSON, NDJSON, SARIF, HTML). This report is then ingested by a robust LangGraph agent that analyzes, organizes, and enriches the findings, providing deep insights with unprecedented speed.

### Key Features

- **Blazing-fast scanning** built in C++ with deterministic results
- **Advanced intelligence layer** powered by Python and LangGraph
- **Multiple output formats** including JSON, NDJSON, SARIF, and HTML
- **Comprehensive security coverage** across processes, network, kernel, and more
- **Risk scoring and compliance assessment** with remediation guidance
- **Fleet-wide analytics** and rarity analysis
- **Extensible rules engine** with MITRE ATT&CK mapping

---

## Quick Start

### Installation

#### Option 1: Install from Debian Package (Recommended)

```bash
# Add the Mazzlabs repository
echo "deb [signed-by=/usr/share/keyrings/mazzlabs-archive-keyring.gpg] https://apt.mazzlabs.works/ stable main" | sudo tee /etc/apt/sources.list.d/mazzlabs.list

# Import the GPG key
curl -fsSL https://apt.mazzlabs.works/mazzlabs-archive-keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/mazzlabs-archive-keyring.gpg

# Update package lists and install
sudo apt update
sudo apt install sys-scan-graph
```

#### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/Mazzlabs/sys-scan-graph.git
cd sys-scan-graph

# Build the core scanner
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Install Python dependencies for intelligence layer
cd agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Basic Usage

#### Using Installed Package

```bash
# Run a basic scan
sys-scan --canonical --modules-summary --min-severity info > report.json

# Run with intelligence layer
sys-scan --canonical --output report.json
sys-scan-agent analyze --report report.json --out enriched_report.json
```

#### Using Source Build

```bash
# Run a basic scan
./build/sys-scan --canonical --modules-summary --min-severity info > report.json

# Run with intelligence layer
./build/sys-scan --canonical --output report.json
python -m sys_scan_graph_agent.cli analyze --report report.json --out enriched_report.json
```

### Generate HTML Report

```bash
# Enable HTML generation in config.yaml, then run:
sys-scan-agent analyze --report report.json --out enriched_v2.json --prev enriched_report.json
```

---

## Documentation

For detailed documentation, see our [comprehensive wiki](docs/wiki/_index.md):

- **[Architecture Overview](docs/wiki/Architecture.md)** - High-level system architecture, core vs intelligence layer responsibilities
- **[Core Scanners](docs/wiki/Core-Scanners.md)** - Scanner implementations, signals, output formats, and schemas
- **[Intelligence Layer](docs/wiki/Intelligence-Layer.md)** - Pipeline stages, LangGraph orchestration, LLM providers, data governance

### Additional Resources

- **[Rules Engine](docs/wiki/Rules-Engine.md)** - Rule file formats, MITRE aggregation, severity overrides, validation
- **[CLI Guide](docs/wiki/CLI-Guide.md)** - Complete command reference
- **[Extensibility](docs/wiki/Extensibility.md)** - Adding custom scanners and rules

---

## Repository Structure

This repository contains:

- **Core Scanner** (`src/`, `CMakeLists.txt`) - High-performance C++ scanning engine
- **Intelligence Layer** (`agent/`) - Python-based analysis and enrichment
- **Rules** (`rules/`) - Security rules and MITRE ATT&CK mappings
- **Documentation** (`docs/wiki/`) - Comprehensive project documentation
- **Tests** (`tests/`, `agent/tests/`) - Test suites for both components

---

## Key Design Principles

- **High-signal, low-noise findings** through aggregation and baseline analysis
- **Deterministic, reproducible results** suitable for CI/CD and compliance
- **Lightweight deployment** with minimal runtime dependencies
- **Extensible architecture** via rules layer and optional intelligence enrichment

---

## Licensing

**Important:** This project uses dual licensing to balance open-source benefits with sustainable commercial development.

- **Core Scanner**: MIT License (C++ components)
- **Intelligence Layer**: Business Source License 1.1 (see [`agent/LICENSE`](agent/LICENSE))
- **Commercial Use**: Intelligence Layer requires commercial license for production use

See [`LICENSE`](LICENSE) for complete licensing details and [`docs/wiki/License-Overview.md`](docs/wiki/License-Overview.md) for comprehensive licensing information.

---

## Support & Community

- **Documentation**: [Wiki](docs/wiki/_index.md) | [GitHub Wiki](https://github.com/Mazzlabs/sys-scan-graph/wiki)
- **Issues**: [GitHub Issues](https://github.com/Mazzlabs/sys-scan-graph/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Mazzlabs/sys-scan-graph/discussions)
- **Security**: See [`SECURITY.md`](SECURITY.md) for vulnerability disclosure

---

<div align="center">
  <img src="assets/Mazzlabs.png" alt="Mazzlabs Logo" width="200"/>
</div>
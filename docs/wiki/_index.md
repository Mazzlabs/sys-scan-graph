# sys-scan-graph Documentation Index

![sys-scan-graph Badge](../../assets/sys-scan-graph_badge.jpg)

Welcome to the comprehensive documentation for sys-scan-graph. This index provides quick access to detailed documentation pages covering all aspects of the project.

## Quick Links

- **[GitHub Repository](https://github.com/Mazzlabs/sys-scan-graph)** - Main project repository
- **[GitHub Wiki](https://github.com/Mazzlabs/sys-scan-graph/wiki)** - Community-contributed documentation and guides
- **[Issues](https://github.com/Mazzlabs/sys-scan-graph/issues)** - Report bugs and request features
- **[Discussions](https://github.com/Mazzlabs/sys-scan-graph/discussions)** - Community discussions and Q&A

## Core Documentation

### Architecture & Design

- **[Architecture Overview](Architecture.md)** - High-level system architecture, core vs intelligence layer responsibilities
- **[Core Scanners](Core-Scanners.md)** - Scanner implementations, signals, output formats, and schemas
- **[Intelligence Layer](Intelligence-Layer.md)** - Pipeline stages, LangGraph orchestration, LLM providers, data governance

### Components & Features

- **[Rules Engine](Rules-Engine.md)** - Rule file formats, MITRE aggregation, severity overrides, validation
- **[Risk Model](Risk-Model.md)** - Risk and probability modeling, weights, calibration, CLI helpers
- **[Baseline & Rarity](Baseline-Rarity-Novelty.md)** - Baseline database, process novelty embeddings, fleet rarity
- **[Correlation & Compliance](Correlation-Compliance-ATTACK.md)** - Correlation heuristics, compliance normalization, ATT&CK coverage

### Operations & Performance

- **[Performance & Determinism](Performance-Determinism-Provenance.md)** - Performance baselines, canonicalization, reproducible builds, provenance, signing
- **[Fleet Reporting](Fleet-and-Rarity-Reporting.md)** - Fleet reports and rarity generation
- **[CLI Guide](CLI-Guide.md)** - Command-line interface for core and agent functionality
- **[CI and SARIF Integration](CI-and-SARIF-Integration.md)** - Running scans in CI pipelines and SARIF upload

### Development & Extensibility

- **[Extensibility](Extensibility.md)** - Adding scanners, rule packs, heuristics, knowledge packs, follow-up tools
- **[Testing & CI](Testing-and-CI.md)** - Test suites, CI/CD setup, performance thresholds, SARIF integration
- **[Roadmap](Roadmap.md)** - Current roadmap, planned features, and development priorities

## Licensing & Legal

- **[License Overview](License-Overview.md)** - Complete licensing structure and terms
- **[BSL FAQ](../LEGAL/BSL-FAQ.md)** - Business Source License 1.1 explanation and usage guidelines
- **[Contributing Guide](../../CONTRIBUTING.md)** - How to contribute to the project
- **[Code of Conduct](../../CODE_OF_CONDUCT.md)** - Community standards and guidelines
- **[Security Policy](../../SECURITY.md)** - Security disclosure and vulnerability reporting

## Quick Start

If you're new to sys-scan-graph, start here:

1. **[Installation Guide](Installation.md)** - Complete installation instructions for all platforms
2. **[README](../../README.md)** - Project overview and basic setup
3. **[CLI Guide](CLI-Guide.md)** - Essential command-line usage
4. **[Core Scanners](Core-Scanners.md)** - Understanding scanner capabilities

## Release Management

- **[Release Notes Template](../Release-Notes-Template.md)** - Template for creating release notes
- **[Installation Guide](Installation.md)** - Installation instructions for all platforms

## Community Resources

- **GitHub Wiki**: <https://github.com/Mazzlabs/sys-scan-graph/wiki>
  - User guides and tutorials
  - Configuration examples
  - Troubleshooting tips
  - Integration guides

- **Discussions**: <https://github.com/Mazzlabs/sys-scan-graph/discussions>
  - Ask questions
  - Share use cases
  - Discuss features and roadmap

## Support

- **Issues**: <https://github.com/Mazzlabs/sys-scan-graph/issues>
  - Bug reports
  - Feature requests
  - Technical support

- **Security**: See [Security Policy](../../SECURITY.md) for vulnerability disclosure

## License

This documentation is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).

---

![Mazzlabs Logo](../../assets/Mazzlabs.png)

Last updated: September 2025

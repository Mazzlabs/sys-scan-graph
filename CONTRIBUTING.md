# Contributing to sys-scan-graph

Thank you for your interest in contributing to sys-scan-graph! This document provides guidelines and information for contributors.

## Ways to Contribute

### 🧪 Testing & Quality Assurance

Testing is one of the most valuable contributions you can make:

- **Run the test suites** regularly and report any failures
- **Test on different platforms** (Linux distributions, architectures)
- **Performance testing** - help identify bottlenecks and regressions
- **Integration testing** - test with different configurations and use cases
- **Security testing** - help validate scanner accuracy and coverage

### 🐛 Bug Reports

- Use the [GitHub Issues](https://github.com/Mazzlabs/sys-scan-graph/issues) to report bugs
- Include detailed reproduction steps
- Provide system information and scanner output
- Tag security-related issues appropriately

### 💡 Feature Requests

- Open a [GitHub Discussion](https://github.com/Mazzlabs/sys-scan-graph/discussions) for new features
- Describe the problem you're trying to solve
- Consider how the feature fits with existing architecture
- Be open to alternative solutions

### 📖 Documentation

- Improve existing documentation
- Add examples and tutorials
- Translate documentation
- Create video tutorials or demos

### 🔧 Code Contributions

- Fix bugs or implement features
- Improve performance or reliability
- Add new scanner capabilities
- Enhance the intelligence layer

## Development Setup

### Prerequisites

- **C++ Compiler**: GCC 9+ or Clang 10+
- **CMake**: 3.16+
- **Python**: 3.8+ (for Intelligence Layer)
- **Git**: For version control

### Building from Source

```bash
# Clone the repository
git clone https://github.com/Mazzlabs/sys-scan-graph.git
cd sys-scan-graph

# Build the core scanner
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Optional: Build with tests
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
```

### Setting up the Intelligence Layer

```bash
# Create Python virtual environment
python -m venv agent/.venv
source agent/.venv/bin/activate

# Install dependencies
pip install -r agent/requirements.txt
```

## Testing Guidelines

### Running Tests

```bash
# Core scanner tests
cd build
ctest --output-on-failure

# Intelligence layer tests
cd agent
python -m pytest tests/
```

### Test Categories

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **Performance Tests**: Validate performance characteristics
- **Regression Tests**: Ensure fixes don't break existing functionality

### Writing Tests

- Write tests for new features
- Include edge cases and error conditions
- Test both success and failure scenarios
- Document test setup and expectations

## Code Style Guidelines

### C++ Code

- Follow modern C++17/20 idioms
- Use RAII for resource management
- Prefer `const` correctness
- Use meaningful variable and function names
- Add comments for complex logic

### Python Code

- Follow PEP 8 style guidelines
- Use type hints where possible
- Write docstrings for public functions
- Handle exceptions appropriately

### General

- Write clear, readable code
- Add comments for non-obvious logic
- Keep functions focused and single-purpose
- Use consistent naming conventions

## Pull Request Process

1. **Fork** the repository
2. **Create a feature branch** from `main`
3. **Make your changes** following the guidelines above
4. **Add tests** for new functionality
5. **Update documentation** if needed
6. **Run tests** to ensure everything works
7. **Submit a pull request** with a clear description

### Pull Request Requirements

- **Descriptive title** explaining the change
- **Detailed description** of what was changed and why
- **Reference issues** if applicable
- **Include screenshots** for UI changes
- **List breaking changes** if any

### Review Process

- Maintainers will review your PR
- Address any feedback or requested changes
- Once approved, your PR will be merged
- Your contribution will be acknowledged

## Licensing

By contributing to sys-scan-graph, you agree that your contributions will be licensed under the same terms as the rest of the project:

- **Core Scanner**: Proprietary (based on MIT original)
- **Intelligence Layer**: Business Source License 1.1
- **Documentation**: Creative Commons Attribution 4.0

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a welcoming environment for all contributors.

## Getting Help

- **Documentation**: Check the [wiki](docs/wiki/_index.md) first
- **Discussions**: Use [GitHub Discussions](https://github.com/Mazzlabs/sys-scan-graph/discussions) for questions
- **Issues**: Report bugs via [GitHub Issues](https://github.com/Mazzlabs/sys-scan-graph/issues)

## Recognition

Contributors are recognized in several ways:

- **GitHub Contributors**: Listed in the repository's contributor statistics
- **Changelog**: Mentioned in release notes for significant contributions
- **Documentation**: Credited in relevant documentation sections
- **Community**: Acknowledged in community discussions

Thank you for contributing to sys-scan-graph! 🚀
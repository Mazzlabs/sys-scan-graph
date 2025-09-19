# Synthetic Data Generation Framework

This framework generates realistic synthetic security scan data for training machine learning models to replace LangGraph API calls with local inference.

## Overview

The synthetic data generation system consists of:

- **Producer Agents**: Generate realistic findings for different scanner types
- **Verifier Agents**: Validate data quality and prevent over-generation
- **Generator Orchestrator**: Coordinates producers and verifiers
- **Ground Truth Schema**: Defines the structure of generated data

## Architecture

```
SyntheticDataPipeline
├── ProducerRegistry (8 producers)
│   ├── ProcessProducer
│   ├── NetworkProducer
│   ├── KernelParamsProducer
│   ├── ModulesProducer
│   ├── WorldWritableProducer
│   ├── SuidProducer
│   ├── IocProducer
│   └── MacProducer
├── CorrelationRegistry (3 correlation producers)
│   ├── ProcessNetworkCorrelationProducer
│   ├── FileSystemCorrelationProducer
│   └── KernelCorrelationProducer
├── AdvancedVerificationAgent
│   ├── Schema Validation
│   ├── Consistency Check
│   ├── Realism Assessment
│   ├── Correlation Validation
│   └── Quality Scoring
└── DataTransformationPipeline
    ├── Normalization & Cleaning
    ├── LangChain Enrichment (optional)
    ├── Structure Optimization
    ├── Indexing
    └── Compression
```

## Usage

### Complete Pipeline Execution

```python
from synthetic_data_pipeline import run_synthetic_data_pipeline

# Run complete pipeline with default settings
result = run_synthetic_data_pipeline(
    output_path="synthetic_dataset.json",
    compress=False
)

# Run with custom producer counts
result = run_synthetic_data_pipeline(
    output_path="custom_dataset.json",
    producer_counts={
        "processes": 50,
        "network": 30,
        "kernel_params": 20,
        "modules": 10
    },
    use_langchain=True,  # Requires LangChain installation
    compress=True
)
```

### Advanced Pipeline Usage

```python
from synthetic_data_pipeline import SyntheticDataPipeline

# Initialize pipeline
pipeline = SyntheticDataPipeline(use_langchain=True)

# Execute with full control
result = pipeline.execute_pipeline(
    producer_counts={"processes": 20, "network": 15},
    output_path="advanced_dataset.json",
    output_format="optimized_json",
    compress=False,
    save_intermediate=True  # Save intermediate results for debugging
)

# Check pipeline status
status = pipeline.get_pipeline_status()
print(f"Pipeline stage: {status['stage']}")
print(f"Findings generated: {status['findings_generated']}")
```

### Individual Component Usage

```python
# Use individual components
from producer_registry import registry
from correlation_registry import correlation_registry
from advanced_verification_agent import AdvancedVerificationAgent

# Generate findings
findings = registry.generate_all_findings({"processes": 10, "network": 10})

# Analyze correlations
correlations = correlation_registry.analyze_all_correlations(findings)

# Verify data quality
verifier = AdvancedVerificationAgent()
report = verifier.verify_dataset(findings, correlations)
```

## Producer Types

### Process Producer

Generates process-related security findings:

- Normal processes (systemd, firefox, etc.)
- Suspicious processes (unusual command lines)
- Malicious processes (known malware patterns)
- Edge cases (zombie processes, high CPU usage)

### Network Producer

Generates network-related security findings:

- Normal network connections (standard ports)
- Suspicious connections (unusual ports, foreign addresses)
- Malicious connections (C2 servers, data exfiltration)
- Port scanning activity and service enumeration

### Kernel Parameters Producer

Generates kernel parameter security findings:

- Security-related sysctl parameters
- Network hardening settings
- Memory protection configurations
- File system security options

### Kernel Modules Producer

Generates kernel module analysis findings:

- Loaded kernel modules
- Module dependencies and conflicts
- Security-related module detection
- Unusual or suspicious modules

### World-Writable Files Producer

Generates file permission vulnerability findings:

- World-writable files and directories
- File capabilities detection
- Sticky bit configurations
- Permission escalation risks

### SUID/SGID Binaries Producer

Generates privileged binary security findings:

- SUID/SGID bit detection
- Expected vs unexpected privileged binaries
- Binary path validation
- Privilege escalation risks

### IOC (Indicators of Compromise) Producer

Generates process-based security indicator findings:

- Deleted executable detection
- World-writable process patterns
- Malicious command line patterns
- Process anomaly detection

### MAC (Mandatory Access Control) Producer

Generates MAC status findings:

- AppArmor profile status
- SELinux enforcement state
- grsecurity configuration
- TOMOYO Linux status

## Verifier Types

### Schema Verifier

Ensures generated data matches the ground truth schema structure.

### Coherence Verifier

Validates logical consistency between related findings.

### Realism Verifier

Ensures findings appear realistic based on real-world patterns.

### Abundance Verifier

Prevents over-generation of similar findings.

## Data Structure

Generated data follows the ground truth schema with:

- `enriched_findings`: Array of security findings
- `correlations`: Relationships between findings
- `reductions`: Summary information
- `summaries`: Narrative summaries
- `actions`: Recommended remediation actions

## Configuration

### Producer Counts

Control the number of findings per producer type:

```python
producer_counts = {
    "processes": 50,
    "network": 30,
    "kernel_params": 10,
    "modules": 5
}
```

### Verification Settings

Configure verification behavior:

```python
# Enable/disable verification
verify = True

# Maximum retry iterations
max_iterations = 5
```

## Integration

The synthetic data generator integrates with the existing sys-scan-graph agent framework:

1. **Data Generation**: Produces realistic training data
2. **Quality Assurance**: Verifies data meets quality standards
3. **Model Training**: Provides diverse, realistic datasets
4. **Local Inference**: Supports fine-tuning for local model deployment

## Parallel Processing

The framework includes intelligent parallel processing capabilities to handle large datasets efficiently while respecting system resources.

### Features

- **Conservative Mode**: Uses 50% of CPU cores (max 4) for local development
- **Cloud Mode**: Uses 75% of CPU cores for server/cloud execution
- **Resource Monitoring**: Automatically reduces workers if CPU/memory usage is high
- **Graceful Fallback**: Falls back to sequential processing for small datasets
- **JSON Optimization**: All processing is optimized for JSON format as required by the model

### Parallel Configuration

```python
# Local development (recommended)
pipeline = SyntheticDataPipeline(conservative_parallel=True)  # Uses ~4 workers

# Cloud/server execution
pipeline = SyntheticDataPipeline(conservative_parallel=False)  # Uses ~75% of CPU cores

# Convenience function with parallel control
result = run_synthetic_data_pipeline(
    output_path="dataset.json",
    conservative_parallel=True,  # Safe for local execution
    producer_counts={"processes": 100, "network": 50}
)
```

### Performance Benefits

- **Finding Generation**: 8 producers run in parallel instead of sequentially
- **Correlation Analysis**: 3 correlation producers run in parallel
- **Resource Safety**: Automatic CPU/memory monitoring prevents system overload
- **Scalability**: Handles large datasets efficiently for cloud deployment

### Safety Features

- **Resource Checks**: Monitors CPU and memory usage before parallel execution
- **Worker Limits**: Conservative mode caps workers at 4 for local execution
- **Graceful Degradation**: Reduces workers if system resources are constrained
- **Small Dataset Optimization**: Uses sequential processing for datasets ≤ 2 items

## Files

### Core Pipeline

- `synthetic_data_pipeline.py`: Complete end-to-end pipeline orchestrator
- `producer_registry.py`: Registry for managing all producer instances
- `correlation_registry.py`: Registry for managing correlation producers
- `advanced_verification_agent.py`: Multi-stage data quality verification
- `data_transformation_pipeline.py`: Data transformation and optimization

### Producers

- `base_producer.py`: Abstract base class for all producers
- `process_producer.py`: Process scanner findings producer
- `network_producer.py`: Network scanner findings producer
- `kernel_params_producer.py`: Kernel parameters scanner producer
- `modules_producer.py`: Kernel modules scanner producer
- `world_writable_producer.py`: World-writable files scanner producer
- `suid_producer.py`: SUID/SGID binaries scanner producer
- `ioc_producer.py`: Indicators of Compromise scanner producer
- `mac_producer.py`: Mandatory Access Control scanner producer

### Correlation Producers

- `base_correlation_producer.py`: Base class for correlation analysis
- `process_network_correlation_producer.py`: Process-network relationship analysis
- `filesystem_correlation_producer.py`: File system security correlation analysis
- `kernel_correlation_producer.py`: Kernel parameter correlation analysis

### Testing & Validation

- `test_producers.py`: Producer validation and testing
- `test_pipeline.py`: Complete pipeline testing
- `README.md`: Comprehensive documentation

### Legacy Files (for reference)

- `base_verifier.py`: Legacy verifier base class
- `schema_verifier.py`: Legacy schema verification
- `coherence_verifier.py`: Legacy coherence verification
- `realism_verifier.py`: Legacy realism verification
- `abundance_verifier.py`: Legacy abundance control
- `verifier_orchestrator.py`: Legacy verifier coordinator

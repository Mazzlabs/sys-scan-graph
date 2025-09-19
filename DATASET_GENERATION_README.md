# Massive Synthetic Dataset Generation

Production-ready system for generating massive synthetic datasets optimized for fine-tuning security scan models.

## 🚀 Quick Start

### Generate Massive Dataset (Recommended)
```bash
# From project root directory
./generate_massive_dataset.sh
```

This will generate ~120K+ findings over ~2 hours using GPU optimization.

### Custom Configuration
```bash
# Generate 50K findings in 1 hour
./generate_massive_dataset.sh --batch-size 2500 --max-batches 20 --max-hours 1.0

# Generate without GPU optimization
./generate_massive_dataset.sh --no-gpu --batch-size 2000 --max-batches 15

# Custom output directory
./generate_massive_dataset.sh --output-dir ./my_datasets --batch-size 10000
```

## 📋 Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output-dir`, `-o` | `./massive_datasets` | Output directory for generated datasets |
| `--batch-size`, `-b` | `5000` | Findings per batch |
| `--max-batches`, `-m` | `24` | Maximum number of batches |
| `--max-hours`, `-t` | `2.0` | Maximum runtime in hours |
| `--gpu` | `enabled` | Enable GPU optimization |
| `--no-gpu` | - | Disable GPU optimization |
| `--conservative` | `disabled` | Use conservative parallel processing |

## 🏗️ Architecture

### Core Components
- **DatasetGenerator**: Main orchestration class with resource monitoring
- **SyntheticDataPipeline**: End-to-end pipeline with GPU optimization
- **Parallel Processing**: Multi-threaded/ProcessPoolExecutor for massive parallelization
- **GPU Optimization**: T4-specific worker scaling and resource management

### Data Producers
- **Processes**: System process findings
- **Network**: Network connection and service findings
- **Filesystem**: File system security findings
- **Kernel Parameters**: Kernel security parameter findings
- **Modules**: Kernel module findings
- **IOC**: Indicator of compromise findings
- **MAC**: Mandatory access control findings
- **SUID**: SetUID binary findings

### Correlation Producers
- **Process-Network**: Process to network correlations
- **Filesystem**: File system correlations
- **Kernel**: Kernel parameter correlations

## 📊 Output Structure

```
massive_datasets/
├── batch_001_20250919_143022.json  # Individual batch files
├── batch_002_20250919_143527.json
├── ...
├── generation_report.json          # Comprehensive generation report
└── [compressed files if enabled]
```

### Generation Report Format
```json
{
  "generation_stats": {
    "total_runtime_seconds": 7200.5,
    "total_runtime_hours": 2.0,
    "batches_completed": 24,
    "total_findings": 120000,
    "total_correlations": 24000,
    "findings_per_second": 16.7,
    "gpu_optimized": true,
    "errors": []
  },
  "batch_results": [...],
  "system_info": {
    "cpu_count": 8,
    "memory_gb": 32.0,
    "platform": "linux"
  },
  "output_directory": "./massive_datasets"
}
```

## 🎯 Use Cases

### Fine-tuning Datasets
- Generate 100K+ findings for model training
- Balanced distribution across security domains
- JSON-optimized format for model ingestion
- Correlation analysis for complex relationships

### Performance Testing
- Stress test generation pipeline
- Benchmark GPU vs CPU performance
- Test resource utilization patterns

### Development Testing
- Generate smaller datasets for testing
- Validate pipeline components
- Debug correlation algorithms

## 🔧 Advanced Usage

### Direct Python Execution
```python
from agent.synthetic_data.generate_dataset import DatasetGenerator

# Initialize generator
generator = DatasetGenerator(gpu_optimized=True, conservative_parallel=False)

# Generate dataset
result = generator.generate_massive_dataset(
    output_dir="./custom_datasets",
    batch_size=10000,
    max_batches=10,
    max_runtime_hours=1.5
)

print(f"Generated {result['generation_stats']['total_findings']:,} findings")
```

### Environment Variables
```bash
# Force CPU-only mode
export CUDA_VISIBLE_DEVICES=""

# Set Python path
export PYTHONPATH="$PYTHONPATH:/path/to/project"

# Control parallelism
export OMP_NUM_THREADS=4
```

## 📈 Performance Optimization

### T4 GPU Optimization
- **Worker Scaling**: 8-12 workers (conservative), up to 90% CPU (aggressive)
- **ProcessPoolExecutor**: CPU-bound task optimization
- **Memory Management**: Automatic resource monitoring
- **Batch Processing**: Efficient memory usage patterns

### Resource Monitoring
- Real-time CPU/memory monitoring
- Automatic worker reduction on high utilization
- Graceful degradation to sequential processing
- Signal handling for clean shutdown

## 🛠️ Troubleshooting

### Common Issues

**Import Errors**
```bash
# Ensure you're in the project root
cd /path/to/sys-scan-graph
./generate_massive_dataset.sh
```

**GPU Not Detected**
```bash
# Check GPU availability
nvidia-smi

# Force CPU mode
./generate_massive_dataset.sh --no-gpu
```

**Memory Issues**
```bash
# Reduce batch size
./generate_massive_dataset.sh --batch-size 2000 --max-batches 10

# Use conservative mode
./generate_massive_dataset.sh --conservative
```

**Permission Errors**
```bash
# Make script executable
chmod +x generate_massive_dataset.sh

# Check output directory permissions
mkdir -p ./massive_datasets
```

### Debug Mode
```bash
# Enable verbose output
python3 agent/synthetic_data/generate_dataset.py --output-dir ./debug --batch-size 100 --max-batches 1
```

## 📋 Requirements

- **Python**: 3.7+
- **Memory**: 8GB+ recommended, 16GB+ for large batches
- **Storage**: 10GB+ for massive datasets
- **GPU**: NVIDIA T4 or similar (optional, CPU fallback available)

### Optional Dependencies
- `psutil`: System resource monitoring
- `nvidia-ml-py`: GPU monitoring
- CUDA-compatible GPU for GPU optimization

## 🎯 Expected Performance

| Configuration | Findings/Hour | Memory Usage | CPU Usage |
|---------------|---------------|--------------|-----------|
| T4 GPU (Default) | ~30K-50K | 4-8GB | 60-90% |
| CPU Only | ~10K-20K | 2-4GB | 80-100% |
| Conservative | ~15K-25K | 2-6GB | 40-70% |

*Performance varies based on system configuration and batch size*